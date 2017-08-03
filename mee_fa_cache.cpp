
#include "mee_fa_cache.h"

//TODO: eviction of dirty blocks
//TODO: merge identical read requests

uint16_t get_way(uint64_t address){
    
    //eliminate block index bits
    address = address >> 6;

    //mask tag bits
    address = address & (WAYS-1);

    return address;
}


FACache::FACache(MEESystem* dram, uint32_t size, uint32_t access_latency){
    this->dram = dram;
    this->access_latency = access_latency;
    this->size = size;
}


void FACache::add_response_schedule(uint64_t earliest_cycle, uint64_t address){

    

    while( scheduled_response.count(earliest_cycle) !=0) {

            earliest_cycle++;

            //MEE_DEBUG("scheduling\t" << earliest_cycle);

    }

    scheduled_response[earliest_cycle] = address;

}

void FACache::process_inputs(){

    //TODO: 1 cycle for lookup and 1 cycle for adding miss to DRAM queue

    bool writing;
    uint64_t address;


    if(!read_buffer.empty()){
        writing = false;
        address = read_buffer.front();
        read_buffer.pop();
    }

    else if(!write_buffer.empty()){
        writing = true;
        address = write_buffer.front();
        write_buffer.pop();
    }

    //both are empty
    else{
        return;
    }

    

    //check if it is a hit
    uint16_t way = get_way(address);
    bool hit =  (data_store[way].count(address) !=0 );

    //check mshr hit (i.e. if its a secondary miss
    auto mshr_entry = std::find_if( mshr.begin(), mshr.end(), 
            [address](const Request & r) -> bool { return r.address == address; } );

    bool mshr_hit = mshr_entry != mshr.end();



    if(hit){

        MEE_DEBUG("cache_hit\t0x" << hex << address << " in way " << way);

        //update MRU data 
        
        data_store[way][address].most_recently_used  = current_cycle;

        
        //just set diry bit if its a write
        if(writing){
            data_store[way][address].dirty = true;
            MEE_DEBUG("cache_write_done\t0x" << hex << address);
        }
        //schedule a response if its a read
        else{
            add_response_schedule(current_cycle + access_latency, address);
        }
        
        
    }

    else if(mshr_hit){
      //we put this in a wait buffer and process it later when data 
      //becomes available
      MEE_DEBUG("secondary_miss\t0x" << hex << address);

      Request r = *mshr_entry;

      r.is_write = writing;

      secodary_waits.push_back(r);

    }

    //if its a new request, we send request to DRAM.
    else{

        //prepare a mem request on a miss

        Request r = {address, writing};

        //pass request to DRAM
        dram_read_buff.push(address);


        //search by address
        auto res = std::find_if( mshr.begin(), mshr.end(), 
            [address](const Request & r) -> bool { return r.address == address; } );

        if (res != mshr.end()){
            MEE_DEBUG("misses_under_miss");
        }

        else{
            
            MEE_DEBUG("new_cache_miss\t0x" << hex << address);

        }

        //miss status holding register
        mshr.push_back(r);

    }

    
}


void FACache::process_dram_response(){
    
    if( !dram->is_dram_resp_available() ) return;

    uint64_t address = dram->get_dram_response();

    MEE_DEBUG("DRAM_Cache_resp\t0x" << hex << address);


    //check if respose matches any request

    //auto entry = std::find(mshr.begin(), mshr.end(), address);

     //search by address
    auto mshr_entry = std::find_if( mshr.begin(), mshr.end(), 
            [address](const Request & r) -> bool { return r.address == address; } );


    //make sure we are not snooping someone's request
    if( mshr_entry != mshr.end() ){

        MEE_DEBUG("DRAM->Cache\t0x" << hex << address);

        // //we need to make a space for it
        // //this happens off the critical path while processing misses.
        // //hence we do not need to add extra delay for evictions
        uint16_t way = get_way(address);
        evict_block(way);


        // //place it inside a cache block
        struct CacheBlock block{current_cycle, false};
        data_store[way][address] = block ;

        bool is_write = mshr_entry->is_write;

        if(is_write){
            data_store[way][address].dirty = true;            
            MEE_DEBUG("cache_write_done\t0x" << hex << address);
        }

        else{
            //schedule for the next cycle
            MEE_DEBUG("cache_schedule\t" << current_cycle+CACHE_ACCESS_CYCLES);
            add_response_schedule(current_cycle + CACHE_ACCESS_CYCLES, address);    
        }

        
        //we might have secondary misses, in a wait buffer
        //TODO: better timing model
        for (auto iter = secodary_waits.begin(); 
             iter != secodary_waits.end();) {

            if( iter->address == address ){
                if(iter->is_write) {
                    data_store[way][address].dirty = true;       
                }
                else{
                    MEE_DEBUG("secondary_miss_serviced\t0x" << hex << address);
                    add_response_schedule(current_cycle + CACHE_ACCESS_CYCLES, address);    

                }
                secodary_waits.erase(iter);
            }

            else{
                iter++;
            }

            
        }      

        mshr.erase(mshr_entry);

        
    }
}


void FACache::evict_block(uint16_t way){

    //MEE_DEBUG("attempt evict\t" << data_store.size());
    
    //if not full, no need to evict 
    //standard 64B cache
    if(data_store[way].size()*64 < size/WAYS ) return;

    uint64_t min = current_cycle + 1;
    uint64_t address = 0;
    bool dirty = false;

    //find the LRU block
    for(auto block: data_store[way]){
        if(block.second.most_recently_used < min ){
            address = block.first;
            dirty = block.second.dirty;

        }
    }

    data_store[way].erase(address);

    if(dirty){
        dram_write_buff.push(address);
    }

    MEE_DEBUG("evicting\t0x" << hex << address << "\tdirty\t" << dirty);

}

void FACache::send_dram_req(){

    //we give priority to writes on one cycle, and
    //to reads in another cycle.
    //TODO: a more optimized approach might be to give more weight to reads


    //we do writes when this is true
    static bool do_write = false;


    uint64_t addr = 0;
    bool write_ready = do_write && !dram_write_buff.empty();
    
    //if not writing, do a read
    bool read_ready = !write_ready && !dram_read_buff.empty() ;


    //nothing is ready
    if(!write_ready && !read_ready){
        do_write = !do_write; 
        return;
    }

    if(write_ready){
        addr = dram_write_buff.front();
        MEE_DEBUG("cache writing\t0x" << hex << addr);
    }

    else if(read_ready){
        addr = dram_read_buff.front();
        do_write = false;
    }

    if(dram->can_accept_dram_req(addr) ){
        assert( dram->send_dram_req(do_write, addr) );
        MEE_DEBUG("Cache->DRAM\t0x" << hex << addr);   

        //if written successfully, remove from  queue
        if(do_write)
            dram_write_buff.pop();
        else
            dram_read_buff.pop();
    }   


    do_write = !do_write;    

}



void FACache::tick(){


    current_cycle++;


    //delete any responses that were scheduled to be in the 
    //prev cycle
    if(scheduled_response.count(current_cycle -1 ) != 0){

        scheduled_response.erase(current_cycle -1 );
    }

    //send misses to DRAM
    send_dram_req();    

    //process read request from this cycle
    process_inputs();
    
    //accept any read responses from the DRAM
    process_dram_response();

    
}


void FACache::add_input(bool is_write, uint64_t address){
    
    //fail if input cannot be taken
    assert( can_accept_input() );


    if (is_write) {
        write_buffer.push(address);
        //assert(false && "writes not yet implemented");
    }

    else{
        read_buffer.push(address);
    }
    

}

bool FACache::can_accept_input(){
    
    //check if buffer is full
    return read_buffer.size()  < CACHE_IN_QUEUE_SIZE;
     // &&
     //       mshr.size() < MSHR_SIZE &&
     //       secodary_waits.size() < SECONDARY_BUFF_SIZE;

}


bool FACache::is_output_ready(){

    //check if there is an access scheduled to be returned this cycle

    return ( scheduled_response.count(current_cycle) != 0 );

}


uint64_t FACache::get_output(){
    //check if output is actually available

    assert(is_output_ready() && "getOutput(): no available output");

    //output_read = true;
    //last_output_cycle = current_cycle;

    return scheduled_response[current_cycle];

}


bool FACache::exit_sim() {

    return false;

}
