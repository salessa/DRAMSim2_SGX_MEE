
#include "MEESystem.h"


void MEESystem::tick(){


    current_cycle++;

    //return to the core
    // if(!channelResponse.empty()){
    //     (*readDone)(0, channelResponse.front(), current_cycle);
    //     channelResponse.pop();
    // }

    for (auto obj = simObjects.begin(); obj != simObjects.end(); ++obj){
        (*obj)->tick();
    }


    //check if decryptor has returned any data 
    if(decryptor->is_output_ready()){
        uint64_t addr = decryptor->get_output();
        unsigned channel = mem_sys->findChannelNumber(addr);

        bool is_write = decryptor->output_is_write();

        if(is_write){
          (*writeDone)(channel, addr, current_cycle);   
        }

        else{
          (*readDone)(channel, addr, current_cycle);   
        }
    }


    //check if encryptor is done
    // if(encryptor->is_output_ready()){
    //     uint64_t write_addr = encryptor->get_output();
    //     unsigned channel = mem_sys->findChannelNumber(write_addr);
    //     (*writeDone)(channel, write_addr, current_cycle);   
    // }


    //we responses from mem channels should only be free for 1 cycle    
    if(!channelResponse.empty()){
        channelResponse.pop();
    }
}

bool MEESystem::addTransaction(bool isWrite, uint64_t addr, unsigned channelNum){ 

    MEE_DEBUG("MEE request\t0x" << hex << addr);

    return decryptor->add_input(isWrite, addr);

    
}

bool MEESystem::willAcceptTransaction(uint64_t channel){
    
    
    //TODO: support per channel checking
    return willAcceptTransaction();
    
}


bool MEESystem::willAcceptTransaction(){
    
    //TODO: buffer one request locally. more efficient as writes can happen if 
    //reads are stalled and vice versa
    return decryptor->can_accept_input();

}


void MEESystem::RegisterCallbacks( TransactionCompleteCB *readDone,
	TransactionCompleteCB *writeDone,
	void (*reportPower)(double bgpower, double burstpower, double refreshpower, double actprepower)){


        this->readDone = readDone;
        this->writeDone = writeDone;

}


void power_callback(double a, double b, double c, double d)
{
//  printf("power callback: %0.3f, %0.3f, %0.3f, %0.3f\n",a,b,c,d);
}


MEESystem::MEESystem(MultiChannelMemorySystem *mem_sys_): mem_sys(mem_sys_), current_cycle(0){


    init_sim_objects();

    callbackObj = new MEECallBack(&channelResponse);

    //we want channels to call the function in this module.
    //some of the responses will be read/write requests to crypto metadata and 
    //need to be processed by the MEE, not the CPU

    meeReadCallback = new Callback<MEECallBack, void, unsigned, uint64_t, uint64_t>(callbackObj, &MEECallBack::readCallback);
    meeWriteCallback = new Callback<MEECallBack, void, unsigned, uint64_t, uint64_t>(callbackObj, &MEECallBack::writeCallback);



    for(size_t i = 0; i < mem_sys->channels.size(); i++){
        mem_sys->channels[i]->RegisterCallbacks(meeReadCallback, meeWriteCallback , power_callback); 
    }

}



//***************************************************
bool MEESystem::can_accept_dram_req(uint64_t addr){


    
    for (size_t c=0; c<NUM_CHANS; c++) {
		if (!mem_sys->channels[c]->WillAcceptTransaction())
		{
			return false; 
		}
	}
	return true; 

}

bool MEESystem::send_dram_req(bool is_write, uint64_t addr){
    
    unsigned channel = mem_sys->findChannelNumber(addr);

    MEE_DEBUG("trans_added\t0x" << hex << addr);
    return mem_sys->channels[channel]->addTransaction(is_write, addr);

   
}


bool MEESystem::is_dram_resp_available(){

    return !channelResponse.empty();

}

uint64_t MEESystem::get_dram_response(){
    //we pop data from channel response at the beginning of the next cycle
    uint64_t addr = channelResponse.front();
    return addr;
}

//***************************************************

void MEESystem::init_sim_objects(){

	//on-chip fully associative SRAM cache
    //on a miss, sends DRAM requests
    crypto_cache = new FACache(this, CACHE_SIZE, CACHE_ACCESS_CYCLES);

    simObjects.push_back(crypto_cache);

	//encryption/decryption pipeline:
    //requests are sent to the crypto cache. 
	decryptor = new Decryptor(crypto_cache, this);

	simObjects.push_back( (SimObject*) decryptor);
	

}



