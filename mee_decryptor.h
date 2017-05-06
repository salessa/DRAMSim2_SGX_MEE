

#ifndef DEC_H
#define DEC_H

class Decryptor;

#include "MEESystem.h"
#include "mee_sim_object.h"
#include "mee_fa_cache.h"
#include "mee_pipeline_simple.h"
#include "mee_pipeline_simple.cpp"


#include <unordered_map>
#include <algorithm>
#include <bitset>
#include <vector>
#include <map>
#include <cmath>

using namespace std;

//TODO: move to config header
#define DECRYPTOR_INPUT_QUEUE 8
#define CACHE_UPDATE_QUEUE 8
#define AES_STAGES 10

//do GF mult + XOR + compare MAC
#define CRYPTO_FINALIZE_CYCLES 2

#define MB 1024*1024

#define MAC_REGION_SIZE 60*MB
#define VER_REGION_SIZE 60*MB
#define L0_REGION_SIZE  4*MB
#define L1_REGION_SIZE  MB/2 //?
#define L2_REGION_SIZE  MB/16 //?

#define MAC_PER_CL 8
#define CTR_PER_CL 8



//for now let's use the lowest part of the phycical address 
//for storing meta-data
#define DATA_REGION_START 0
#define MAC_REGION_START 0x800000000000
#define VER_REGION_START MAC_REGION_START + MAC_REGION_SIZE + 64
#define L0_REGION_START  VER_REGION_START + VER_REGION_SIZE + 64
#define L1_REGION_START  L0_REGION_START + L0_REGION_SIZE + 64
#define L2_REGION_START  L1_REGION_START + L1_REGION_SIZE + 64


//if the CPU simulator does not implement a proper TLB,
//it might send the virtual address. 
//this will be problamatic when computing the address for CTR, MAC etc...
//so we mask it first
#define VIRT_ADDR_MASK ~0x0000ffffffff

//mem block, MAC, ctr, L0, L1, L2
const unsigned REQUESTS_PER_BLOCK = 6;


class Decryptor: public SimObject{
    
public:
    Decryptor(FACache *cache_, MEESystem* dram_);

    bool can_accept_input();
    bool is_output_ready();
    uint64_t get_output();
    bool add_input(bool, uint64_t);
    bool output_is_write();
    
    
    //inherited
    void tick() ;
    bool exit_sim() ;
    
    
private:
    FACache *cache;
    MEESystem* dram;

    typedef enum RequestType_{
        BLOCK=0, MAC, VER, L0, L1, L2
    }RequestType;

    #define WRITE_FLAG L2 + 1

    string RequestTypeStr[6];

    void process_active();
    void process_mee_input();
    void process_aes_pipeline();
    void process_final_pipeline();
    uint64_t get_counter_address(uint64_t address);
    int search_trans_by_addr(uint64_t addr);
    int search_waiting_trans(uint64_t addr, RequestType_ type);
    //void process_ctr_response();



    //new requests to the MEE
    queue<uint64_t> input_queue;
    queue<bool> input_type_queue;


    queue<uint64_t> crypto_finalize_queue; //requests that are going through the very last phase 
                                           //(MAC compare, key xor data ...)

    queue<uint64_t> aes_input_queue; 
    queue<uint64_t> output_queue; //response that is ready to be returned to cores/caches
    queue<uint64_t> response_queue;

    queue<bool> output_write_flags;

    queue<uint64_t> cache_update_queue;


    vector<uint64_t> outstanding_ctr_req;
    unordered_map<uint64_t, uint64_t> scheduled_response;
    Pipeline<uint64_t> *aes_pipeline;
    Pipeline<uint64_t> *crypto_finalize_pipeline;

    void update_status(uint64_t addr);
    typedef bitset<REQUESTS_PER_BLOCK + 1> StatusBits; //we need 1 more bit to mark writes
    


    //transactions keeps track of the metadata for each memory block.
    //we search through it using the address of the encrypted block we are reading.
    //since this is timing simulation, we do not need to store the actual meta-data.
    //instead, we only store valid bits that are set when read is completed

//    unordered_map<uint64_t, StatusBits> transactions;    
      vector<StatusBits> transactions_status;
      vector<uint64_t> transactions_addr;

    //outstanding_metadata_reads is used to track what data block each meta-data 
    //read corresponds to. we index into it the address of a DRAM request and get the
    //address of the data block.
    //in an RTL implementation, this will probably be a small tag that gives us an index
    //into an SRAM storing transactions

    //we use multimap since request to the metadata memory block can come
    //form different requests.

    multimap<uint64_t, uint64_t> outstanding_metadata_reads;


    vector<uint64_t> outstanding_dram;



    void process_response();
    void read_response();


    //address ranges for ver, MAC, L0, L1, L2, L3
    //we assume the heighrst part of the address space is used for this
    //uint64_t ver_start, ver_end, mac_start, mac_end, l0_start, l0_end, l1_start, l1_end, l2_start, l2_end;

    RequestType get_block_type(uint64_t type);
    void finish_crypto();
    bool send_dram_req(bool, uint64_t addr);    
    bool send_cache_req(bool, uint64_t addr);    
    uint64_t get_data_addr(uint64_t addr);
    uint64_t get_MAC_address(uint64_t data_addr);
    uint64_t get_VER_address(uint64_t data_addr);
    uint64_t get_L0_address(uint64_t data_addr);
    uint64_t get_L1_address(uint64_t data_addr);
    uint64_t get_L2_address(uint64_t data_addr);


    uint64_t current_active_request;
    //int current_trans_index;
    bool active_write ;
    bool request_is_active ;
    uint16_t active_request_status;


};

#endif
