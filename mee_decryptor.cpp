
#include "mee_decryptor.h"



Decryptor::Decryptor(FACache *cache_, MEESystem *dram_):
  cache(cache_),dram(dram_),
  RequestTypeStr{"BLOCK", "MAC", "VER", "L0", "L1", "L2"}, 
  current_active_request(0),
  active_write(false),
  request_is_active(false) {


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


// uint64_t Decryptor::get_data_addr(uint64_t addr){
    

//     auto type =  get_block_type(addr);
//     unsigned offset;
//     switch(type){
//         case(BLOCK):
//             //print warning
//             break;
//         case(MAC):
//             offset = ( addr - MAC_REGION_START)*MAC_PER_CL;
            

//             break;
//         case(VER):

//             break;
//         case(L0):
            
//             break;
//         case(L1):
            
//             break;
//         case(L2):
            
//             break;
//     }


// }

uint64_t get_address_offset(uint64_t data_addr, uint64_t region_size){

    uint64_t offset_bits = log2(region_size);

    //remove the lower (offset_bit) bits
    //xxxxxxxxxxx to xxxxxx00000
    uint64_t masked = (data_addr >> offset_bits) << offset_bits;

    //xxxxxxxxxxx ^ xxxxxx00000 = xxxxx
    uint64_t offset = masked ^ data_addr;

    return offset;

}

//TODO: repetitive....
//define function that takes region size and region start address after testing

inline uint64_t Decryptor::get_MAC_address(uint64_t data_addr){
    data_addr = data_addr & VIRT_ADDR_MASK; 
    uint64_t offset = (data_addr - DATA_REGION_START) /MAC_PER_CL; 
    //get_address_offset(data_addr, MAC_REGION_SIZE);
    return (MAC_REGION_START + offset) & ~0x3f; 
}

inline uint64_t Decryptor::get_VER_address(uint64_t data_addr){
    data_addr = data_addr & VIRT_ADDR_MASK; 
    uint64_t offset = (data_addr - DATA_REGION_START) /CTR_PER_CL;
    //get_address_offset(data_addr, VER_REGION_SIZE);

    return (VER_REGION_START + offset) & ~0x3f; 
}

inline uint64_t Decryptor::get_L0_address(uint64_t data_addr){
    data_addr = data_addr & VIRT_ADDR_MASK; 
    uint64_t offset = (data_addr - DATA_REGION_START)/(CTR_PER_CL*CTR_PER_CL);
    //get_address_offset(data_addr, L0_REGION_SIZE);
    return (L0_REGION_START + offset) & ~0x3f; ;
}

inline uint64_t Decryptor::get_L1_address(uint64_t data_addr){
    data_addr = data_addr & VIRT_ADDR_MASK; 
    uint64_t offset = (data_addr - DATA_REGION_START)/std::pow(CTR_PER_CL, 3);
    //get_address_offset(data_addr, L1_REGION_SIZE);
    return (L1_REGION_START + offset) & ~0x3f; 
}

inline uint64_t Decryptor::get_L2_address(uint64_t data_addr){
    data_addr = data_addr & VIRT_ADDR_MASK; 
    uint64_t offset = (data_addr - DATA_REGION_START)/std::pow(CTR_PER_CL, 4);
    //get_address_offset(data_addr, L2_REGION_SIZE);
    return (L2_REGION_START + offset) & ~0x3f; 
}



int Decryptor::search_trans_by_addr(uint64_t addr){

    for (unsigned i = 0; i < transactions_addr.size(); ++i){
        
        if (transactions_addr[i] == addr){
            return i;
        }
    
        
    }

    return -1;

}

int Decryptor::search_waiting_trans(uint64_t addr, RequestType_ type){

    for (unsigned i = 0; i < transactions_addr.size(); ++i){
        

        if (transactions_addr[i] == addr && 
            !transactions_status[i].test( type )){

            return i;
        }
    
        
    }

    return -1;

}

//**************************

bool Decryptor::send_dram_req(bool is_write, uint64_t addr){

    if(dram->can_accept_dram_req(addr)){

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

void Decryptor::finish_crypto(){
    
    //this function is called when a block and all of it's meta-data is fetched
    //at this point, the relevant counter values have also passed through the
    //AES pipeline. also, data must have already been read from SRAM at this point
    //hence, we just need to:
    //-  do GF-mult(1 cycle)
    // - compare output with MAC(1 cycle)
    // - XOR key stream with ... (can be done in parallel with or at the end of the above operation)
    // - total: 2 cycles

    
    //schedule a finished event to happen 2 cycles from now.

    if (crypto_finalize_queue.empty()) return;
    
    uint64_t addr = crypto_finalize_queue.front();
    crypto_finalize_queue.pop();


    MEE_DEBUG("finalizing_crypto\t0x" << hex <<addr);




    crypto_finalize_pipeline->add_input(addr);


    //make cache updates "ready"

    int trans_idx = search_trans_by_addr(addr);

    //@@bool is_write = transactions[addr].test(WRITE_FLAG);

    bool is_write = transactions_status[trans_idx].test(WRITE_FLAG);

    if(is_write){
        cache_update_queue.push( get_L0_address(addr) );
        cache_update_queue.push( get_L1_address(addr) );
        cache_update_queue.push( get_L2_address(addr) );
        cache_update_queue.push( get_MAC_address(addr) );
        cache_update_queue.push( get_VER_address(addr) );
    }


    //remove entry for this request
    //@@transactions.erase(addr); 

    transactions_status.erase( transactions_status.begin() + trans_idx );
    transactions_addr.erase( transactions_addr.begin() + trans_idx );




}


Decryptor::RequestType Decryptor::get_block_type(uint64_t type){

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

    return BLOCK;


}

void Decryptor::process_active(){

     //TODO: this is sub-optimal as we are not sending cache requests when DRAM 
    //request queue if full (i.e if BLOCK request cannot be sent, counter/MAC cache 
    //cannot be read). this will probably have a small effect on performance.

    //generate DRAM requests for a secure read request if we are
    //not done requesting everything (MAC, CTR, ...)


    uint64_t addr;

    switch(active_request_status){
        case(BLOCK):
            if ( send_dram_req(false, current_active_request) ){
                active_request_status = VER;
                MEE_DEBUG("BLOCK req\t0x" << hex << current_active_request);
            }
            break;
        case(MAC):
            addr = get_MAC_address(current_active_request);
            if(send_cache_req(false, addr)){
                active_request_status = L0;
                
                outstanding_metadata_reads.insert(
                    make_pair(addr, current_active_request) );

                MEE_DEBUG("MAC req\t0x" << hex << addr << "\t0x" << hex << current_active_request);
            }
            break;
        case(VER):
                
            addr = get_VER_address(current_active_request);
            if(send_cache_req(false, addr)){
                active_request_status = MAC;
                
                outstanding_metadata_reads.insert(
                    make_pair(addr, current_active_request) );

                MEE_DEBUG("VER req\t0x" << hex << addr << "\t0x" << hex << current_active_request);
            }
            break;
        case(L0):
                
            addr = get_L0_address(current_active_request);
            if(send_cache_req(false, addr)){
                active_request_status = L1;
                
                outstanding_metadata_reads.insert(
                    make_pair(addr, current_active_request) );

                MEE_DEBUG("L0 req\t0x" << hex << addr << "\t0x" << hex << current_active_request);
            }
            break;
        case(L1):
                
            addr = get_L1_address(current_active_request);
            if(send_cache_req(false, addr)){
                active_request_status = L2;
                
                outstanding_metadata_reads.insert(
                    make_pair(addr, current_active_request) );

                MEE_DEBUG("L1 req\t0x" << hex << addr << "\t0x" << hex << current_active_request);
            }
            break;
        case(L2):
                
            addr = get_L2_address(current_active_request);
            if(send_cache_req(false, addr)){
                //we are done requesting everything
                request_is_active = false;
                
                outstanding_metadata_reads.insert(
                    make_pair(addr, current_active_request) );

                MEE_DEBUG("L2 req\t0x" << hex << addr << "\t0x" << hex << current_active_request);
            }
            break;
    }


    
    


}


/*void Decryptor::mee_process_write(){

    uint64_t addr;
    switch(active_request_status){
        case(MAC):
            addr = get_MAC_address(current_active_request);
            if(send_cache_req(false, addr)){
                active_request_status = L0;
                
                outstanding_metadata_reads.insert(
                    make_pair(addr, current_active_request) );

                MEE_DEBUG("MAC req\t0x" << hex << addr);
            }
            break;
        case(VER):
                
            addr = get_VER_address(current_active_request);
            if(send_cache_req(false, addr)){
                active_request_status = MAC;
                
                outstanding_metadata_reads.insert(
                    make_pair(addr, current_active_request) );

                MEE_DEBUG("VER req\t0x" << hex << addr);
            }
            break;
        case(L0):
                
            addr = get_L0_address(current_active_request);
            if(send_cache_req(false, addr)){
                active_request_status = L1;
                
                outstanding_metadata_reads.insert(
                    make_pair(addr, current_active_request) );

                MEE_DEBUG("L0 req\t0x" << hex << addr);
            }
            break;
        case(L1):
                
            addr = get_L1_address(current_active_request);
            if(send_cache_req(false, addr)){
                active_request_status = L2;
                
                outstanding_metadata_reads.insert(
                    make_pair(addr, current_active_request) );

                MEE_DEBUG("L1 req\t0x" << hex << addr);
            }
            break;
        case(L2):
                
            addr = get_L2_address(current_active_request);
            if(send_cache_req(false, addr)){
                //we are done requesting everything
                request_is_active = false;
                
                outstanding_metadata_reads.insert(
                    make_pair(addr, current_active_request) );

                MEE_DEBUG("L2 req\t0x" << addr);
            }
            break;
    }

}*/

void Decryptor::process_mee_input(){
    

    //a memory request is processed as follows (cycle numbers ignore possible stalls):
    //cycle 0: allocate space in table for outstanding requests (a CAM searched by address or tag)
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

    

    if(request_is_active){


        process_active();

    }


    bool process_new_request = !input_queue.empty() & !request_is_active;
    if(process_new_request){

        //allocate space for it in the SRAM
        //in RTL, this would be the same as storing the address 
        //and updating the head/tail of the storage
        StatusBits status;
        status.reset();
    
        current_active_request = input_queue.front();         
        active_write = input_type_queue.front();


        MEE_DEBUG("processing\t0x" << hex << current_active_request);

        //for writes, we are not going to read the BLOCK
        //we start fetching from the VER, and set block as ready
        if(active_write){
            MEE_DEBUG("write_request\t0x" << hex << current_active_request);
            status.set(BLOCK);
            active_request_status = VER;    
            status.set(WRITE_FLAG);
        }

        else{
            active_request_status = BLOCK;    
        }
    

        //@@transactions[current_active_request] = status;

        transactions_status.push_back(status);
        //current_trans_index = transactions_status.size()-1;

        transactions_addr.push_back( current_active_request );
        
        

        input_queue.pop();
        input_type_queue.pop();
        request_is_active = true;
        
    }
    
}


void Decryptor::update_status(uint64_t addr){

    auto type = get_block_type(addr);
    auto entry = outstanding_metadata_reads.find(addr);

    uint64_t data_addr; 
    if(type==BLOCK){
        data_addr = addr;
    }
    else {
        data_addr = entry->second;    
        outstanding_metadata_reads.erase( entry );
    }
    
    //@@bool sram_hit = transactions.count(data_addr) > 0;

    int trans_idx = search_waiting_trans(data_addr, type);

    bool sram_hit = trans_idx  != -1;

    if(sram_hit){
        
        MEE_DEBUG(RequestTypeStr[type]  << "_READY\t0x" << hex << addr << "\t0x" << hex << data_addr );

        //@@transactions[data_addr].set(type);
        transactions_status[trans_idx].set(type);
        
        //check if that request has all what it needs and 
        //start decryption/re-encryption

        //@@ bool ready = transactions[data_addr].test(L2) &&
        //              transactions[data_addr].test(L1) &&
        //              transactions[data_addr].test(L0) &&
        //              transactions[data_addr].test(MAC) &&
        //              transactions[data_addr].test(VER)  &&
        //              transactions[data_addr].test(BLOCK);

        bool ready = transactions_status[trans_idx].test(L2) &&
                     transactions_status[trans_idx].test(L1) &&
                     transactions_status[trans_idx].test(L0) &&
                     transactions_status[trans_idx].test(MAC) &&
                     transactions_status[trans_idx].test(VER)  &&
                     transactions_status[trans_idx].test(BLOCK);

        if( ready ){
            MEE_DEBUG("ALL_READY\t0x" << hex << data_addr);
            crypto_finalize_queue.push(data_addr);
            
        }


    }
    else{
        MEE_DEBUG("WARNING: unknown request\t0x" << hex << addr << "\t0x" << hex << data_addr)
    }

}


//read queue the cache and DRAM responses
void Decryptor::read_response(){

    if( dram->is_dram_resp_available() ){
        uint64_t addr = dram->get_dram_response();

        //avoid snooping responses for the ctr/mac cache
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

void Decryptor::process_response(){
    
    //when a DRAM response arrives
    //1. determine the type of response (cycle 1)
    //2. use tag of request and type of request to index and write into the right SRAM array (cycle 2)
    //3. feed the right input into the AES queue (cycle 2, 3, 4, 5) - latency already captured 
    //by queuing delay inside aes_input_queue

    //the source of inaccuracy here is that we update the table in 1 cycle.
    //(step 2 above). the effect of this shall not be too much

    if( response_queue.empty() ) return;
    
    uint64_t addr = response_queue.front(); //dram->get_dram_response();
    response_queue.pop();

    //MEE_DEBUG("DRAM response\t0x"<< hex << addr);
    
    //match request with an outstanding request and modify bit in SRAM
    //uint64_t data_addr = get_data_addr(addr);


    auto type = get_block_type(addr);

    //these are counter values and need to pass through 
    //an AES pipeline to compute a keysteeam or a MAC
    //(the MAC is )
    if( type == VER ) {

        //we need to decrypt 64 bytes, so we need 4 AES blocks
        
        //HACK: feeding 0's into the pipline is like introducing a bubble.
        //having 3 bubbles before feeding the actual address will effectively give us
        //the latency we need
        aes_input_queue.push(0);
        aes_input_queue.push(0);
        aes_input_queue.push(0);
        aes_input_queue.push(addr);

        MEE_DEBUG("VER AES Start\t0x" << hex << addr);

    }
    
    //counters from L0, L1, L2 are used to mask the MAC, so we only need 1 block
    else if (type == L0 || type == L1 || type == L2  ){

        MEE_DEBUG("AES Start\t0x" << hex << addr);
        aes_input_queue.push(addr);
    }

    //other values just need to be stored
    //NOTE: in an RTL implementation, we would still need to store some
    //data from fetched blocks on top of passing it through the AES pipeline
    else if(type == BLOCK || type == MAC){
        update_status(addr);
    }


    else{
        MEE_DEBUG("unknown req\t0x" << hex << addr);
    }

        
    
    
}


void Decryptor::process_final_pipeline(){

    //inputs to the pipeline are added by the finalize_crypto function.
    uint64_t output = crypto_finalize_pipeline->tick();

    if(output != 0){

        MEE_DEBUG("done_processing\t0x" << hex << output);
       
        output_queue.push(output);
    }

    //if we have pending writes to the caches...
    if(!cache_update_queue.empty()){
        bool ret = send_cache_req(true, cache_update_queue.front());

        if(ret){
            cache_update_queue.pop();
        }
    }


}

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





void Decryptor::tick(){


    process_response(); //process responses that was enqueued the prev cycles

    //read new response. 
    //calling this second helps introduce a 1 cycle latency before any response is processed
    read_response(); 

    process_mee_input();  
    process_aes_pipeline();
    process_final_pipeline();
    finish_crypto();
    current_cycle++;
    
    

} 

bool Decryptor::add_input(bool is_write, uint64_t address){
    
//    assert(can_accept_input() && "Decryptor: cannot take input this cycle" );

    //MEE_DEBUG("Cypto module\t" << address);
    input_queue.push(address);
    input_type_queue.push(is_write);

    MEE_DEBUG("new request\t0x"<< hex << address);

    assert( get_block_type(address) == BLOCK && "Address space partitioning not correct");

    return true;

}

bool Decryptor::can_accept_input(){


    return input_queue.size() < DECRYPTOR_INPUT_QUEUE && 
           cache_update_queue.size() <= CACHE_UPDATE_QUEUE;

}

bool Decryptor::is_output_ready(){

    return !output_queue.empty();

}

uint64_t Decryptor::get_output(){

//    assert(is_output_ready() && "No output available");

    auto ret = output_queue.front();
    output_queue.pop();

    return ret;

}


bool Decryptor::exit_sim() {

    return false;

}
