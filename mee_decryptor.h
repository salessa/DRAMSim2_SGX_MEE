
#ifndef DEC_H
#define DEC_H

//#define TETRIS
//#define PMAC

class Decryptor;

#include "mee_conf.h"
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


//mem block, MAC, ctr, L0, L1, L2
const unsigned REQUESTS_PER_BLOCK = 11;


class Decryptor: public SimObject{
    
public:
    Decryptor(FACache *cache_, FACache *prefetch_buff_, MEESystem* dram_, uint64_t, uint64_t);

    bool can_accept_input();
    bool is_output_ready();
    uint64_t get_output();
    bool add_input(bool, uint64_t);
    bool output_is_write();
    
    
    //inherited
    void tick() ;
    bool exit_sim() ;

    //used for printing stats every epoch
    uint64_t get_branch_bytes();
    uint64_t get_unmerged_branch_bytes();
    uint64_t get_split_ctr_encryptions();
    uint64_t get_increment_ctr_encryptions();
    uint64_t get_working_set_bytes();
    uint64_t get_merge_count();
    void update_split_ctr(uint64_t data_addr);
    void update_increment_ctr(uint64_t data_addr);
    
    
private:
    FACache *cache;
    FACache *prefetch_buff;
    MEESystem* dram;

    typedef enum RequestFlag_{
        BLOCK=0, MAC, VER, L0, L1, L2, L3, L4, L5, PATCH_BLOCK, BLOCK_EXTRA,
        WRITE_FLAG
    }RequestFlag;


    string RequestTypeStr[REQUESTS_PER_BLOCK];

    void process_active();
    void process_mee_input();
    void process_aes_pipeline();
    void process_final_pipeline();
    uint64_t get_counter_address(uint64_t address);
    int search_trans_by_addr(uint64_t addr);
    int search_waiting_trans(uint64_t addr, RequestFlag_ type);
    //void process_ctr_response();



    //new requests to the MEE
    queue<uint64_t> input_queue;
    queue<bool> input_type_queue;


    queue<uint64_t> crypto_finalize_queue; //requests that are going through the very last phase 
                                           //(MAC compare, key xor data ...)

    queue<uint64_t> aes_input_queue; 
    queue<uint64_t> output_queue; //response that is ready to be returned to cores/caches
    queue<uint64_t> response_queue;

    queue<uint64_t> dram_write_queue;

    queue<bool> output_write_flags;
    queue<bool> write_flags;

    queue<uint64_t> cache_update_queue;

    queue<uint64_t> patch_request_queue;


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

      //these are "parallel" arrays.
      vector<StatusBits> transactions_status;
      vector<uint8_t> mac_blocs_read;
      vector<uint64_t> transactions_addr;


      

    //outstanding_metadata_reads is used to track what data block each meta-data 
    //read corresponds to. we index into it the address of a DRAM request and get the
    //address of the data block.
    //in an RTL implementation, this will probably be a small tag that gives us an index
    //into an SRAM storing transactions

    //we use multimap since request to the metadata memory block can come
    //form different requests.
    multimap<uint64_t, uint64_t> outstanding_metadata_reads;

    multimap<uint64_t, uint64_t> outstanding_superblock_reads;


    vector<uint64_t> outstanding_dram;



    void process_response();
    void read_response();


    //address ranges for ver, MAC, L0, L1, L2, L3
    //we assume the heighrst part of the address space is used for this
    //uint64_t ver_start, ver_end, mac_start, mac_end, l0_start, l0_end, l1_start, l1_end, l2_start, l2_end;

    RequestFlag get_block_type(uint64_t type);
    void finish_crypto();
    bool send_dram_req(bool, uint64_t addr);    
    bool send_cache_req(bool, uint64_t addr);    
    uint64_t get_data_addr(uint64_t addr);
    uint64_t get_MAC_address(uint64_t data_addr);
    uint64_t get_VER_address(uint64_t data_addr);
    uint64_t get_L0_address(uint64_t data_addr);
    uint64_t get_L1_address(uint64_t data_addr);
    uint64_t get_L2_address(uint64_t data_addr);
    uint64_t get_L3_address(uint64_t data_addr);
    uint64_t get_L4_address(uint64_t data_addr);
    uint64_t get_L5_address(uint64_t data_addr);

    bool is_patched(uint64_t address);
    uint64_t get_patch_addr(uint64_t ver_address);
    void request_extra_blocks();
    void process_patch_RW();
    void update_patch(uint64_t data_addr);
    void merge_counters(uint64_t data_addr);
    bool send_data_req(bool is_write, uint64_t addr);

    void fetch_ctr_node(RequestFlag current_node, RequestFlag next_node, uint64_t node_addr, uint64_t data_addr, bool last_node);  



    //*****************
    //these variables keep track of data associated with an active request
    //an active request is one for which mem read requests (read MAC, CTR etc.. are being generated)

    uint64_t active_address; //the address of the data block we are reading
    bool active_is_write ;
    bool request_is_active; //true if there is an active address currently
    RequestFlag_ active_request_status;

    //in our new scheme, we need to read multiple data blocks for veryfying integiry
    //this variable keeps track of the number of data blocks already requested
    //for the base line case, this will have a max value of 1
    uint16_t active_requested_count;

    //*****************

    //we are not storing all DRAM data in the mem simulator. 
    //but we need to keep track of counter patching since it affects timing

    struct CounterPatch{

        //64 bit counter per 64B mem block. 
        //we will not have a super block size of 64*64B(4KB), so this array is more than enough
		uint64_t patches[64];

		//1 bit per 64B mem block that indicates if counter for that element has been patched
		bool patch_status[64];

	};

    //if a memory block's counter has been patched/branched, we will add it
    //to this table, which is indxed by the address of the block address aligned 
    //to the superblock size boundary
    unordered_map<uint64_t, CounterPatch> counter_patch;


    //we track another one with patch disabled 
    unordered_map<uint64_t, CounterPatch> counter_patch_unmerged;


    //*****************
    //track the number of times each touched memory block is read and written
    //used for computing stats
    unordered_map<uint64_t, uint64_t>  mem_block_accesses;

    //tracks number of writes
    unordered_map<uint64_t, uint64_t>  mem_block_writes;

    uint64_t counter_merges;

    //******************

    unordered_map<uint64_t, uint64_t> split_counters;
    unordered_map<uint64_t, uint64_t> increment_counters;

    uint64_t split_counters_reenc;

    uint64_t increment_counters_merges;
    uint64_t increment_counters_reenc;


};

#endif
