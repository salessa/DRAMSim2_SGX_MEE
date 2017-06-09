#ifndef MEE_SYS_H
#define MEE_SYS_H

class MEESystem;
namespace DRAMSim{
	class MultiChannelMemorySystem;
};

#include "mee_conf.h"
#include "mee_utils.h"
#include "Callback.h"
#include "MultiChannelMemorySystem.h"
#include <vector>
#include <queue>
#include "mee_sim_object.h"
#include "mee_fa_cache.h"
#include "mee_decryptor.h"
//#include "mee_encryptor.h"
//#include "MEE/authenticator.h"
//#include "MEE/rw_handler.h"


using namespace std;
using namespace DRAMSim;


class MEESystem {
public:
	
	bool addTransaction(bool isWrite, uint64_t addr, unsigned channelNum);
	void RegisterCallbacks( TransactionCompleteCB *readDone,
	TransactionCompleteCB *writeDone,
	void (*reportPower)(double bgpower, double burstpower, double refreshpower, double actprepower));
	bool willAcceptTransaction(uint64_t channel);
	bool willAcceptTransaction();
	void tick();

	MEESystem(MultiChannelMemorySystem *mem_sys_, ostream &dramsim_log_ );
	~MEESystem();


	uint64_t get_dram_response();
	bool is_dram_resp_available();
	bool send_dram_req(bool is_write, uint64_t addr);
	bool can_accept_dram_req(uint64_t addr);

    void printStats(bool final_stats);


private:
    ostream &dramsim_log;

	//vector<MemorySystem*> channels;
	MultiChannelMemorySystem *mem_sys;
	TransactionCompleteCB *readDone, *writeDone;
	uint64_t current_cycle;

	vector< SimObject* > simObjects;
	
	TransactionCompleteCB *meeReadCallback,*meeWriteCallback;
	void init_sim_objects();


	class MEECallBack{
		public:

			MEECallBack(queue<uint64_t>* readQueue_):readQueue(readQueue_) {}

			void readCallback(unsigned id, uint64_t address, uint64_t clock_cycle){
				readQueue->push(address);

			}

			void writeCallback(unsigned id, uint64_t address, uint64_t clock_cycle){
				//we don't really care about write complete events
			}		

		private:
			queue<uint64_t>* readQueue;

	};
	
	MEECallBack *callbackObj;
    queue<uint64_t>	channelResponse;

	FACache* crypto_cache;
	FACache* prefetch_buffer;
	Decryptor* decryptor;
	//Encryptor* encryptor;
	
};



#endif
