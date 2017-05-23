
#include "MEESystem.h"
#include <sstream>
#include <fstream>



//we are not making these constants since
//we want them to be configurable

static unsigned CACHE_SIZE = 4*1024;

static unsigned CTR_SUPER_BLOCK_SIZE = 512;
static unsigned MAC_SUPER_BLOCK_SIZE = 512;

void load_mee_config();
void dump_config(string);


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
          (*writeDone)(channel, addr, current_cycle-1);   
        }

        else{
          (*readDone)(channel, addr, current_cycle-1);   
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


    
    std::ostringstream config_log;


    load_mee_config();

    config_log << "MEE_CACHE_SIZE\t" << CACHE_SIZE/1024 << "KB\n";
    config_log << "MAC_SUPER_BLOCK_SIZE\t" << MAC_SUPER_BLOCK_SIZE << "B\n";
    config_log << "CTR_SUPER_BLOCK_SIZE\t" << CTR_SUPER_BLOCK_SIZE << "B\n";

#ifdef TETRIS
    config_log << "CTR_OPT_ENABLED\t" << "Y\n";
#else
    config_log << "CTR_OPT_ENABLED\t" << "N\n";
#endif


#ifdef PMAC
    config_log << "MAC_OPT_ENABLED\t" << "Y\n";
#else
    config_log << "MAC_OPT_ENABLED\t" << "N\n";
#endif

    dump_config(config_log.str());


    MEE_DEBUG("MEE_CACHE_SIZE:\t" << CACHE_SIZE/1024 << "KB");
    

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
	decryptor = new Decryptor(crypto_cache, this, 
                              MAC_SUPER_BLOCK_SIZE, CTR_SUPER_BLOCK_SIZE);

	simObjects.push_back( (SimObject*) decryptor);
	

}




//=======================
//these functions load MEE settings from environment variables

unsigned read_from_env(const char* var_name, unsigned default_val){
    
    char *val = getenv(var_name);

    if(val != NULL){
        return unsigned( atoi(val) );
    }

    else{
        return default_val;
    }


}

void load_mee_config(){


    CTR_SUPER_BLOCK_SIZE = read_from_env("CTR_SUPER_BLOCK_SIZE", CTR_SUPER_BLOCK_SIZE);
    
    MAC_SUPER_BLOCK_SIZE = read_from_env("MAC_SUPER_BLOCK_SIZE", MAC_SUPER_BLOCK_SIZE);

    CACHE_SIZE = read_from_env("MEE_CACHE_SIZE", CACHE_SIZE);

    
}

void dump_config(string configs){
    
    ofstream config_file;
    config_file.open ("mee.cfg");
    config_file << configs << endl;
    config_file.close();

}
