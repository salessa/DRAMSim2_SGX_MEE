#include "mee_decryptor.h"



//we are not making these constants since
//we want them to be configurable

static uint64_t CTR_SUPER_BLOCK_SIZE;
static uint64_t MAC_SUPER_BLOCK_SIZE;

static uint64_t MAC_SUPER_BLOCKS;
static uint64_t MAC_SUPER_BLOCK_MASK;

static uint64_t CTR_SUPER_BLOCK_MASK;





Decryptor::Decryptor(FACache *cache_, MEESystem *dram_, uint64_t mac_super_block_size,
    uint64_t ctr_super_block_size):
  cache(cache_),dram(dram_),
  RequestTypeStr{"BLOCK", "MAC", "VER", "L0", "L1", "L2", "PATCH_BLOCK"}, 
  active_address(0),
  active_is_write(false),
  request_is_active(false) {


    CTR_SUPER_BLOCK_SIZE = ctr_super_block_size;
    MAC_SUPER_BLOCK_SIZE = mac_super_block_size;

    MAC_SUPER_BLOCKS = MAC_SUPER_BLOCK_SIZE/64;
    MAC_SUPER_BLOCK_MASK = ~(MAC_SUPER_BLOCK_SIZE-1);

    CTR_SUPER_BLOCK_MASK = ~(CTR_SUPER_BLOCK_SIZE-1);

    MEE_DEBUG("CTR_SUPER_BLOCK_SIZE:\t" << CTR_SUPER_BLOCK_SIZE);    
    MEE_DEBUG("MAC_SUPER_BLOCK_SIZE:\t" << MAC_SUPER_BLOCK_SIZE);

    


   current_cycle = 0;
   aes_pipeline = new Pipeline<uint64_t>(AES_STAGES);

   crypto_finalize_pipeline = new Pipeline<uint64_t>(CRYPTO_FINALIZE_CYCLES);






   MEE_DEBUG("MAC\t0x" << hex <<  MAC_REGION_START << "\t0x" << hex << MAC_REGION_START + MAC_REGION_SIZE << "\n" <<
            "VER\t0x" << hex  <<  VER_REGION_START << "\t0x" << hex << VER_REGION_START + VER_REGION_SIZE << "\n" <<
            "L0\t0x" << hex   <<  L0_REGION_START << "\t0x" << hex << L0_REGION_START + L0_REGION_SIZE << "\n" <<
            "L1\t0x" << hex   <<  L1_REGION_START << "\t0x" << hex << L1_REGION_START + L1_REGION_SIZE << "\n" <<
            "L2\t0x" << hex   <<  L2_REGION_START << "\t0x" << hex << L2_REGION_START + L2_REGION_SIZE << "\n");

}

//**************************


//TODO: repetitive....
//define function that takes region size and region start address after testing



//get the address for the MAC associated with a data block
inline uint64_t Decryptor::get_MAC_address(uint64_t data_addr){
    
    ////if the CPU simulator does not implement a proper TLB, it might send the raw virtual address. 
    //this will be problamatic when computing the address for CTR, MAC etc...
    //so we mask it first
    data_addr = data_addr & VIRT_ADDR_MASK; 

    uint64_t offset = (data_addr - DATA_REGION_START) /MAC_PER_CL; 

    uint64_t ret = (MAC_REGION_START + offset) & ~0x3f; //align to a 64B block

    assert(ret < MAC_REGION_START + MAC_REGION_SIZE && "Incorrect Address");
    
    return ret;
}

inline uint64_t Decryptor::get_VER_address(uint64_t data_addr){
    data_addr = data_addr & VIRT_ADDR_MASK; 
    uint64_t offset = (data_addr - DATA_REGION_START) /VER_PER_CL;

    return (VER_REGION_START + offset) & ~0x3f; 
}

inline uint64_t Decryptor::get_L0_address(uint64_t data_addr){
    data_addr = data_addr & VIRT_ADDR_MASK; 
    uint64_t offset = (data_addr - DATA_REGION_START)/(CTR_PER_CL*CTR_PER_CL);
    return (L0_REGION_START + offset) & ~0x3f; ;
}

inline uint64_t Decryptor::get_L1_address(uint64_t data_addr){
    data_addr = data_addr & VIRT_ADDR_MASK; 
    uint64_t offset = (data_addr - DATA_REGION_START)/std::pow(CTR_PER_CL, 3);
    return (L1_REGION_START + offset) & ~0x3f; 
}

inline uint64_t Decryptor::get_L2_address(uint64_t data_addr){
    data_addr = data_addr & VIRT_ADDR_MASK; 
    uint64_t offset = (data_addr - DATA_REGION_START)/std::pow(CTR_PER_CL, 4);
    return (L2_REGION_START + offset) & ~0x3f; 
}


inline uint64_t Decryptor::get_patch_addr(uint64_t ver_addr){
    ver_addr = ver_addr & VIRT_ADDR_MASK; 
    return PATCH_REGION_START; //TODO: track free list (using bit set) and return values
}



//this gives us the index of the first transaction with 
//this physical address
int Decryptor::search_trans_by_addr(uint64_t addr){

    for (unsigned i = 0; i < transactions_addr.size(); ++i){
        
        if (transactions_addr[i] == addr){
            return i;
        }        
    }

    return -1;

}


//there might be multiple outstanding reads/writes to the same data block
//in this case, we need to match incoming meta-data(CTR, MAC ...) with the 
//right data block request. this function returns the index of the oldest 
//transaction that is waiting for a meta data
    
int Decryptor::search_waiting_trans(uint64_t addr, RequestFlag_ type){

    for (unsigned i = 0; i < transactions_addr.size(); ++i){
        

        if (transactions_addr[i] == addr && 
            !transactions_status[i].test( type )){ //check this outstanding request 
                                                   //is waiting for a specific type of metadata

            return i;
        }
    
        
    }

    return -1;

}

//**************************



bool Decryptor::send_dram_req(bool is_write, uint64_t addr){

    if(dram->can_accept_dram_req(addr)){

        MEE_DEBUG("DRAM_Data_Req:\t0x" << hex << addr);

        bool ret = dram->send_dram_req(is_write, addr);
        if(ret) outstanding_dram.push_back(addr);
        return ret;

    }

    return false;
}


bool Decryptor::send_cache_req(bool is_write, uint64_t addr){
    
    if(cache->can_accept_input()){
        cache->add_input(is_write, addr);
        return true;
    }

    return false;
}




//*************************
//this function is called after a block and all of it's meta-data is fetched
    //at this point, the relevant counter values have also passed through the
    //AES pipeline. also, top level counter must have already been read from SRAM at this point
    //hence, we just need to:
    //-  do GF-mult(1 cycle)
    // - compare output with MAC(1 cycle)
    // - XOR key stream with ... (can be done in parallel with or at the end of the above operation)
    // - total: 2 cycles

void Decryptor::finish_crypto(){
    
    if (crypto_finalize_queue.empty()) return;
    
    uint64_t addr = crypto_finalize_queue.front();
    crypto_finalize_queue.pop();


    MEE_DEBUG("finalizing_crypto\t0x" << hex <<addr);

    //schedule a finished event to happen 2 cycles from now.
    crypto_finalize_pipeline->add_input(addr);


    //make cache updates "ready"

    int trans_idx = search_trans_by_addr(addr);

    //@@bool is_write = transactions[addr].test(WRITE_FLAG);

    bool is_write = transactions_status[trans_idx].test(WRITE_FLAG);

    if(is_write){

        MEE_DEBUG("write_done\t0x" << hex << addr);

        //on a write, all counters and MAC need to be updated.
        //since we are enqueuing the updates (which means they will not be sent to cache
        //for the next multiple cycles), we do not need to account for extra latency 
        //to compute MAC etc...

        cache_update_queue.push( get_L0_address(addr) );
        cache_update_queue.push( get_L1_address(addr) );
        cache_update_queue.push( get_L2_address(addr) );
        cache_update_queue.push( get_MAC_address(addr) );
        cache_update_queue.push( get_VER_address(addr) );

#ifdef TETRIS
        //we need to update the patch status
        update_patch(addr);
#endif


    }


    //remove entry for this request
    //@@transactions.erase(addr); 

    write_flags.push(is_write);

    transactions_status.erase( transactions_status.begin() + trans_idx );
    transactions_addr.erase( transactions_addr.begin() + trans_idx );

#ifdef PMAC
    mac_blocs_read.erase(mac_blocs_read.begin() + trans_idx);
#endif    

}


void Decryptor::merge_counters(uint64_t data_addr){
    
    uint64_t addr_aligned = data_addr & CTR_SUPER_BLOCK_MASK;
    
    bool is_identical = true;
    for (unsigned i = 0; i < CTR_SUPER_BLOCK_SIZE/64-1; ++i){

        is_identical = is_identical && 
                        ( counter_patch[addr_aligned].patches[i] == counter_patch[addr_aligned].patches[i+1] );

    }

    if(is_identical){
        
        counter_patch.erase(addr_aligned);
        MEE_DEBUG("mergeing_patches 0x" << hex << data_addr);

        //TODO: collect stat
        //patch_cnt -= num_grouped_blocks;
        //merged_count+= num_grouped_blocks;
	}
    

}


void Decryptor::update_patch(uint64_t data_addr){

    uint64_t addr_aligned = data_addr & CTR_SUPER_BLOCK_MASK;

    //we are branching out the counter for the first time
    if( !is_patched(data_addr) ){

        CounterPatch p;
        //HACK: since we are not properly tracking counters, we will simply initialize all of them
        //to a single value. since a 64 bit (or 56 bit) counter will not overflow, this 
        //will work fine.

        for (unsigned i = 0; i < CTR_SUPER_BLOCK_SIZE/64-1; ++i)
        {
            p.patches[i] = 1;
        }

        counter_patch[addr_aligned] = p;

        MEE_DEBUG("new_patch: 0x" << hex << addr_aligned << "\t0x" << hex << data_addr);

    }


    unsigned block_idx =  ( data_addr & (CTR_SUPER_BLOCK_SIZE-1) )/CTR_SUPER_BLOCK_SIZE ;

    //we increment the counter for the block that was must updated
    counter_patch[addr_aligned].patches[block_idx]++;
    MEE_DEBUG("update_patch: 0x" << hex << data_addr);

    //we check if the counter can be merged
    merge_counters(data_addr);
    
}

//when a read request returns from memory, we use this function to figure out
//what type of data it is
Decryptor::RequestFlag Decryptor::get_block_type(uint64_t type){

    if(type >= VER_REGION_START && type <= (VER_REGION_START + VER_REGION_SIZE)){
        return VER;
    }

    if(type >= MAC_REGION_START && type <= (MAC_REGION_START + MAC_REGION_SIZE)){
        return MAC;
    }

    if(type >= L0_REGION_START && type <= (L0_REGION_START + L0_REGION_SIZE) ){
        return L0;
    }

    if(type >= L1_REGION_START && type <= (L1_REGION_START + L1_REGION_SIZE)) {
        return L1;
    }

    if(type >= L2_REGION_START && type <= (L2_REGION_START + L2_REGION_SIZE)){
        return L2;
    }

    if(type >= PATCH_REGION_START && type <= (PATCH_REGION_START + PATCH_REGION_SIZE)){
        return PATCH_BLOCK;
    }



    return BLOCK;


}


bool Decryptor::send_data_req(bool is_write, uint64_t addr){
    
#ifndef PMAC
    return send_dram_req(is_write, addr);

#else 
    //TODO: send request to a direct mapped cache
    return send_dram_req(is_write, addr);    

#endif

    //for tetris case -> send request to buffer

}


void Decryptor::request_extra_blocks(){


    //this is the first block in the super block
    uint64_t base_addr = active_address & MAC_SUPER_BLOCK_MASK;

    uint64_t addr;


    //in our new scheme we need to request multiple memory blocks
    //to be able to verify integrity.
    //so we have to generate the address to read the right address

    if(!active_is_write){ //only need to read multiple blocks for reads
        addr = base_addr + 64 * (active_requested_count);
    }




    if ( send_data_req(false, addr) ){

        //keep track of data we are requesting for the purpose of 
        if(addr != active_address){
            
            outstanding_superblock_reads.insert(
                    make_pair(addr, active_address) );
        }

        active_requested_count++;


        //we need to check we have requested an entire super block before proceeding to fetching other meta data

        bool unfinished_requests =  !active_is_write && ( active_requested_count < MAC_SUPER_BLOCKS );

        if(unfinished_requests) {
            //we will still need to read more data in the next block
            active_request_status = BLOCK_EXTRA;
        }

        else{
            request_is_active = false;
            active_requested_count = 0;
        }


        MEE_DEBUG("EXTRA_BLOCK req\t0x" << hex << addr << "\t0x" << hex << active_address);
    }


}



//generate DRAM requests (data, MAC, CTR, ...) for a secure read/write request.

//it takes multiple cycles to send all the requests
void Decryptor::process_active(){

     //TODO: this is sub-optimal as we are not sending cache requests when DRAM 
    //request queue if full (i.e if BLOCK request cannot be sent, counter/MAC cache 
    //cannot be read). this will probably have a small effect on performance.



    uint64_t addr;

    //this implements a state machine. 
    //we begin by request a BLOCK in the first cycle
    //in the next cycle we request a MAC and so on...

    switch(active_request_status){

        case(BLOCK): //this is the starting state
            if ( send_data_req(false, active_address) ){
                active_request_status = VER;
                MEE_DEBUG("BLOCK req\t0x" << hex << active_address);

                request_is_active = false;

                break;
            }

        case (BLOCK_EXTRA):
            request_extra_blocks();
            break;

        case(MAC):
            addr = get_MAC_address(active_address);
            if(send_cache_req(false, addr)){

#ifdef PMAC                
                //for writes, we don't need to read the blocks
                if(active_is_write) request_is_active = false;
                else active_request_status = BLOCK_EXTRA; 
#else
                if(active_is_write) request_is_active = false;
                else active_request_status = BLOCK;
#endif
                
                outstanding_metadata_reads.insert(
                    make_pair(addr, active_address) );

                MEE_DEBUG("MAC req\t0x" << hex << addr << "\t0x" << hex << active_address);
            }
            break;

        case(VER):
                
            addr = get_VER_address(active_address);
            if(send_cache_req(false, addr)){
                active_request_status = L0;
                
                outstanding_metadata_reads.insert(
                    make_pair(addr, active_address) );

                MEE_DEBUG("VER req\t0x" << hex << addr << "\t0x" << hex << active_address);
            }
            break;
            
        case(L0):
                
            addr = get_L0_address(active_address);
            if(send_cache_req(false, addr)){
                active_request_status = L1;
                
                outstanding_metadata_reads.insert(
                    make_pair(addr, active_address) );

                MEE_DEBUG("L0 req\t0x" << hex << addr << "\t0x" << hex << active_address);
            }
            break;

        case(L1):
                
            addr = get_L1_address(active_address);
            if(send_cache_req(false, addr)){
                active_request_status = L2;
                
                outstanding_metadata_reads.insert(
                    make_pair(addr, active_address) );

                MEE_DEBUG("L1 req\t0x" << hex << addr << "\t0x" << hex << active_address);
            }
            break;

        case(L2):
            addr = get_L2_address(active_address);
            if(send_cache_req(false, addr)){
                
#ifdef PMAC   
                //in our scheme, we need to read the MAC for both reads and writes
                active_request_status = MAC;
#else
                //in the base line scheme, we will simply compute a new MAC
                if(active_is_write) request_is_active = false; // we are done!
                else active_request_status = MAC; //go fetch the MAC
#endif
                
                outstanding_metadata_reads.insert(
                    make_pair(addr, active_address) );

                MEE_DEBUG("L2 req\t0x" << hex << addr << "\t0x" << hex << active_address);
            }
            break;

        default:
            assert(false && "Invalid state!");

    }

}


//this is the function that takes data off of a request queue
void Decryptor::process_mee_input(){
    

    //a memory request is processed as follows (cycle numbers ignore possible stalls):
    //cycle 0: allocate space in table for outstanding requests (a CAM searched by address)
    //cycle 0: request the memory block(512 bits)
    //cycle 1: request block with version number (512 bits) - remeber performing integrity checking requires the full mem block
    //cycle 2: request MAC for data (56 bits) 
    //cycle 3: request cache block containing L0 (512 bits)
    //cycle 4: request cache block containing L1 (512 bits)
    //cycle 5: request cache block containing L2 (512 bits)
    //when all data available -> start compute
    
    //size of table structure (assume 50 bits address itself is used instead of tag): 
    //4*512 + 56 + 50  = 2154 bits ~ 269.25 bytes
    //if allow 16 outstanding requests -> 16*270 ~4.2KB
    //if allow 8 outstanding requests -> 8*270 ~2.1KB


    //if we are not done sending requests for MAC, CTR, etc ....
    //we proceed to do that

    if(request_is_active){

        process_active();

    }


    //we can process a new request once we are done generating MAC, CTR ... requests
    //for a previous requests
    bool process_new_request = !input_queue.empty() & !request_is_active;
    if(process_new_request){

        //allocate space for it in the SRAM
        //in RTL, this would be the same as storing the address 
        //and updating the head/tail of the storage
        StatusBits status;
        status.reset();
    
        active_address = input_queue.front();
        active_is_write = input_type_queue.front();


        MEE_DEBUG("processing\t0x" << hex << active_address);

        //for writes, we are not going to read the BLOCK
        //we start fetching from the VER, and set block as ready
        if(active_is_write){
            MEE_DEBUG("write_request\t0x" << hex << active_address);
            status.set(BLOCK);
            status.set(BLOCK_EXTRA);
            status.set(WRITE_FLAG);
#ifndef PMAC
            //the baseline scheme does not need a MAC to be fetched on write
            status.set(MAC);
#endif

        }

//        else{

// #ifdef TETRIS
//             active_request_status = BLOCK_EXTRA;
// #else
//             active_request_status = BLOCK;    
// #endif

            active_request_status = VER;    
//        }
    
        transactions_status.push_back(status);
        //current_trans_index = transactions_status.size()-1;
        transactions_addr.push_back( active_address );
        mac_blocs_read.push_back(0);

        

        input_queue.pop();
        input_type_queue.pop();
        request_is_active = true;

        
    }
    
}


//*********************************************
//this function is used to update the status of outstanding requests
//it is called when a certain data is ready
//i.e. data arrives from memory, CTR has passed through AES pipeline
void Decryptor::update_status(uint64_t addr){

    //FIXME: is 1 cycle too optimistic for this?

    auto type = get_block_type(addr);
    auto entry = outstanding_metadata_reads.find(addr);


#ifdef PMAC
    //a data block might have been requested to check a MAC associated with 
    // a super block
    auto super_block_entry = outstanding_superblock_reads.find(addr);
    bool mac_verify_read = super_block_entry != outstanding_superblock_reads.end();
    
    if(type == BLOCK && mac_verify_read ){    
        type = BLOCK_EXTRA;
    }

#endif

#ifdef TETRIS
    //for this purpose, the patch block is the same as VER
    if(type == PATCH_BLOCK){
        
        MEE_DEBUG("PATCH_BLOCK_DONE \t0x" << hex << addr)
        type = VER;

    }
#endif

    uint64_t data_addr; 

    if(type == BLOCK){

        data_addr = addr;

    }

#ifdef PMAC
    //this can only happen if MAC merging scheme is enabled
    else if(type == BLOCK_EXTRA){
        data_addr = super_block_entry->second;
        outstanding_superblock_reads.erase(super_block_entry);
    }
#endif

    else {

        //erase from our outstanding metadata request list
        data_addr = entry->second;    
        MEE_DEBUG("removing_meta:0x" << hex << addr << hex << "\t0x" << hex << data_addr);
        outstanding_metadata_reads.erase( entry );
    }
    


    
    int trans_idx = search_waiting_trans(data_addr, type);
    bool sram_hit = trans_idx  != -1;




    if(sram_hit){
        
        //if it's a meta data, we just set the right flag in the transaction status
        //to indicate its ready
        if(type != BLOCK_EXTRA){
            MEE_DEBUG(RequestTypeStr[type]  << "_READY\t0x" << hex << addr << "\t0x" << hex << data_addr );

            transactions_status[trans_idx].set(type);
        }   

        //other wise, have to count the number of MAC super blocks we have read
        //(this count does not include the block we are actually interested in)
        else{
            mac_blocs_read[trans_idx]++;
            MEE_DEBUG("MAC_BLOCKS_READ\t0x"<<  hex << addr << "\t0x" << hex << data_addr );
            if(mac_blocs_read[trans_idx] == MAC_SUPER_BLOCKS - 1){
                transactions_status[trans_idx].set(BLOCK_EXTRA);
                MEE_DEBUG("MAC_BLOCKS_READY\t0x"<< hex << data_addr );
            }

        }
        
        //check if that request has all what it needs and 
        //start decryption/re-encryption
        bool ready = transactions_status[trans_idx].test(L2) &&
                     transactions_status[trans_idx].test(L1) &&
                     transactions_status[trans_idx].test(L0) &&
                     transactions_status[trans_idx].test(MAC) &&
                     transactions_status[trans_idx].test(VER)  && //this will be ready when either branched ctr or VER is read.
                     transactions_status[trans_idx].test(BLOCK);

#ifdef PMAC
        //when using PMACs, we also need to wait until all data blocks 
        //in the super block are read
        ready = ready && transactions_status[trans_idx].test(BLOCK_EXTRA);
#endif

        if( ready ){
            MEE_DEBUG("ALL_READY\t0x" << hex << data_addr);
            crypto_finalize_queue.push(data_addr);
            
        }


    }
    else{
        MEE_DEBUG("WARNING: unknown request\t0x" << hex << addr << "\t0x" << hex << data_addr)
    }

}


//read and queue the cache and DRAM responses
void Decryptor::read_response(){



    if( dram->is_dram_resp_available() ){
        uint64_t addr = dram->get_dram_response();

        //to avoid snooping responses for the ctr/mac cache
        //we make sure the address corresponds to something we requested.
        //in an actual hardware, there probably won't be such bus sharing
        auto search = std::find(outstanding_dram.begin(), outstanding_dram.end(),
                  addr);

        if(search != outstanding_dram.end()){
            response_queue.push(addr);
            outstanding_dram.erase(search);
            MEE_DEBUG("dram->queue\t0x" << hex << addr);
        }
    }


    if(cache->is_output_ready()){
        uint64_t addr = cache->get_output();
        MEE_DEBUG("cache->queue\t0x" << hex << addr);
        response_queue.push(addr);
    }

}


bool Decryptor::is_patched(uint64_t address){

#ifdef TETRIS    
    uint64_t addr_aligned = address & CTR_SUPER_BLOCK_MASK;

    MEE_DEBUG("check_patch: 0x" << hex << addr_aligned << "\t0x" << hex << address);

    //if a counter is not branched/patched, we do not keep track of it.
    //so just checking it is in the table is sufficient 
    return counter_patch.count(addr_aligned) > 0;	
    
#else
    return false;
#endif
}


//******************
//processes responses returned from DRAM and meta-data caches
void Decryptor::process_response(){
    
    //when a DRAM response arrives
    //1. determine the type of response - i.e. data block, MAC ... (cycle 1)
    //2. use tag of request and type of request to index and write into the right SRAM array (cycle 2)
    //3. feed the right input into the AES queue (cycle 2, 3, 4, 5) - latency already captured 
    //by queuing delay inside aes_input_queue

    //the source of inaccuracy here is that we update the table in 1 cycle.
    //(step 2 above). the effect of this shall not be too much

    if( response_queue.empty() ) return;
    
    uint64_t addr = response_queue.front(); //dram->get_dram_response();
    response_queue.pop();

    //MEE_DEBUG("DRAM response\t0x"<< hex << addr);


    //1. determine the type of response - i.e. data block, MAC
    auto type = get_block_type(addr);

    
    //for the regular MEE implementation, is_patched will always return false.
    //so this same code can be used in both types of simulations

    //get data address
    auto entry = outstanding_metadata_reads.find(addr);
    uint64_t data_addr = entry->second;
    if( type == VER && is_patched(data_addr) ) {
        //if the block is patched, it means the VER value is a pointer, not an actual counter;
        //so we fetch the value that is pointed to.
        uint64_t patch_addr = get_patch_addr(addr);
        patch_request_queue.push(patch_addr);

    

        //we are done processing the VER
        outstanding_metadata_reads.erase( entry );


        outstanding_metadata_reads.insert(
                    make_pair(patch_addr, data_addr) );


        MEE_DEBUG("Requesting Patch\t0x" << hex << addr << "\t0x" << hex << data_addr);


    }

    //unpatched VER and PATCH blocks are processed as counters
    //these are counter values and need to pass through  an AES pipeline.
    //We will later use the output of the AES pipeline to encrypt/decrypt and compute MAC
    //(note that we assume the MAC is XOR'd with the keystream)
    else if(type == PATCH_BLOCK ||  type == VER ){ 
         //we need to encrypt/decrypt 64 bytes, so we need 4 AES blocks
            
            //HACK: feeding 0's into the pipline is like introducing a bubble.
            //having 3 bubbles before feeding the actual address will effectively give us
            //the latency we need
            aes_input_queue.push(0);
            aes_input_queue.push(0);
            aes_input_queue.push(0);
            aes_input_queue.push(addr);

            MEE_DEBUG("VER AES Start\t0x" << hex << addr);
    }
    
    //counters from L0, L1, L2 are used to mask the MAC (not for encryption/decryption)
    //so we only need 1 block
    else if (type == L0 || type == L1 || type == L2  ){

        MEE_DEBUG("AES Start\t0x" << hex << addr);
        aes_input_queue.push(addr);
    }

    //other values just need to be stored temporarily
    
    else if(type == BLOCK || type == MAC){
        update_status(addr);
    }


    else{
        MEE_DEBUG("unknown req\t0x" << hex << addr);
    }

        
    
    
}


//we use a dummy pipeline at the end to add the extra latenciec that are required
//for reading scratchpad comparing MAC, XOR'ing key streams etc ...
void Decryptor::process_final_pipeline(){

    //inputs to the pipeline are added by the finalize_crypto function.
    uint64_t output = crypto_finalize_pipeline->tick();

    if(output != 0){

        MEE_DEBUG("done_processing\t0x" << hex << output);
       
        output_queue.push(output);
        output_write_flags.push( write_flags.front() ) ;
        write_flags.pop();
    }

    //if we have pending writes to the caches...
    if(!cache_update_queue.empty()){
        bool ret = send_cache_req(true, cache_update_queue.front());

        if(ret){
            cache_update_queue.pop();
        }
    }


}

//this reads outputs from the AES pipeline and
//update the state of a request
void Decryptor::process_aes_pipeline(){
    
    
    if( !aes_input_queue.empty() ){
        uint64_t addr = aes_input_queue.front();
        aes_input_queue.pop();
        aes_pipeline->add_input(addr);
    }
    else{
        aes_pipeline->add_input(0);   
    }
    
    uint64_t output = aes_pipeline->tick();

    //0 output indicates a bubble (or intentional delay) - so we ignore it
    if(output!=0){
        MEE_DEBUG("AES_DONE\t0x"<< hex<< output);
        update_status(output);
    }


    
}


//*********************************
//when a "branched" block is discovered, a new read request is 
//add to a request queue. this function dequeues and processes requests 
//to a branched counter

void Decryptor::process_patch_RW(){

    if( patch_request_queue.empty() ) return;

    uint64_t addr = patch_request_queue.front();

    if(send_cache_req (false ,addr) ){
        patch_request_queue.pop();
    }

}



//this function has to be called every cycle
void Decryptor::tick(){


    current_cycle++;

    if(!output_queue.empty()) output_queue.pop();
    if(!output_write_flags.empty()) output_write_flags.pop();


    process_patch_RW();

    process_response(); //process responses that was enqueued the prev cycles

    //calling this after process response helps introduce a 1 cycle latency before any response is processed
    read_response(); 

    process_mee_input();  
    process_aes_pipeline();
    process_final_pipeline();
    finish_crypto();
    
} 



//the core/caches uses this function to send memory requests
bool Decryptor::add_input(bool is_write, uint64_t address){
    
    //assert(can_accept_input() && "Decryptor: cannot take input this cycle" );
    
    if (!can_accept_input()) {
        MEE_DEBUG("Warning: Decryptor: should not take input this cycle");
    }

    //MEE_DEBUG("Cypto module\t" << address);
    input_queue.push(address);
    input_type_queue.push(is_write);

    MEE_DEBUG("new request\t0x"<< hex << address);

    assert( get_block_type(address) == BLOCK && "Address space partitioning not correct");

    return true;

}

bool Decryptor::can_accept_input(){


    return input_queue.size() < DECRYPTOR_INPUT_QUEUE && 
           cache_update_queue.size() < CACHE_UPDATE_QUEUE && 
           outstanding_dram.size() < DRAM_REQ_OUTSTANDING;

}


bool Decryptor::is_output_ready(){

    return !output_queue.empty();

}

//the cores/caches use this function to know which memory request has completed this cycle
//returns the address of the request that has completed
uint64_t Decryptor::get_output(){

//    assert(is_output_ready() && "No output available");

    auto ret = output_queue.front();


    return ret;

}

bool Decryptor::output_is_write(){

    if(output_write_flags.empty()) return false;

    bool ret = output_write_flags.front();
    MEE_DEBUG("is_write_ret:" << ret);
    return ret;


}

bool Decryptor::exit_sim() {

    return false;

}
