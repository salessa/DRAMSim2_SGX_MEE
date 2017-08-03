

#ifndef FA_CACHE_H
#define FA_CACHE_H

class FACache; //to handle circular includes

#include <vector>
#include "MEESystem.h"
#include "mee_sim_object.h"
#include "mee_utils.h"

#include <cassert>
#include <unordered_map>
#include <queue>
#include <cstdint>
#include <unordered_set>

using namespace std;

#define CACHE_IN_QUEUE_SIZE 2
#define MSHR_SIZE 32
#define SECONDARY_BUFF_SIZE 16
#define WAYS 8

class FACache: public SimObject{

public:

    //memory system to pass misses to
    FACache(MEESystem*, uint32_t, uint32_t);


    void add_input(bool, uint64_t);
    
    bool can_accept_input();
    bool is_output_ready();
    uint64_t get_output();

    //inherited
    void tick() ;
    bool exit_sim() ;
    
private:
    MEESystem* dram;
    uint32_t size;
    uint32_t access_latency;
    
    queue<uint64_t> write_buffer;
    queue<uint64_t> read_buffer;
    queue<uint64_t> ready_misses;

    unordered_map<uint64_t, uint64_t> scheduled_response;


    struct CacheBlock{
        uint64_t most_recently_used;
        bool dirty;
    };

    struct Request
    {
        uint64_t address;
        bool is_write;
    };

    
    unordered_map<uint64_t, CacheBlock> data_store[WAYS];

    //pending DRAM requests
    queue<uint64_t> dram_read_buff;
    queue<uint64_t> dram_write_buff; //for evicted dirty lines

    //miss status handling registers
    vector<Request> mshr;
    vector<Request> secodary_waits;


    void add_response_schedule(uint64_t, uint64_t);
    void process_inputs();
    void process_dram_response();
    void evict_block(uint16_t way);
    void send_dram_req();

};


#endif
