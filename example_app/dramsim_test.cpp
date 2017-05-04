


#include <stdio.h>
#include "dramsim_test.h"
#include <cassert>
#include <cstdlib>


#define ERR_OUT(str)  std::cerr<< "\033[31m" << str <<endl << "\033[0m" << dec;


#define TEST_SINGLE false
#define TEST_SEQ false
#define TEST_RAND true

/* callback functors */
void some_object::read_complete(unsigned id, uint64_t address, uint64_t clock_cycle)
{
    //printf("[Callback] read complete: %d 0x%lx cycle=%lu\n", id, address, clock_cycle);
    assert(!stat_new && "Previous Stat Not Cleared");

    stat_new = true;
    stat_address = address;
    stat_cycle = clock_cycle;
    stat_is_write = false;

    capture_stat();

}

void some_object::write_complete(unsigned id, uint64_t address, uint64_t clock_cycle)
{
    //printf("[Callback] write complete: %d 0x%lx cycle=%lu\n", id, address, clock_cycle);

    assert(!stat_new && "Previous Stat Not Cleared");

    stat_new = true;
    stat_address = address;
    stat_cycle = clock_cycle;
    stat_is_write = true;

    capture_stat();


}

/* FIXME: this may be broken, currently */
void power_callback(double a, double b, double c, double d)
{
//  printf("power callback: %0.3f, %0.3f, %0.3f, %0.3f\n",a,b,c,d);
}



void some_object::capture_stat(){
    if(!stat_new) return;


    bool found = false;
    for (auto i = sim_stats.begin(); i != sim_stats.end(); ++i) {
        if (i->addr == stat_address && i->finished_cycle==0) {
            i->finished_cycle = stat_cycle;
            found = true;
            break;
        }
        
    }

    stat_new = false;


    if(!found) ERR_OUT("Unknown request\t0x" << hex << stat_address);

}

string some_object::dump_and_clear(){
    return "";
}


void some_object::check_stats(){
    for (auto i = sim_stats.begin(); i != sim_stats.end(); ++i) {

        bool completed = i->finished_cycle != 0;

        if(!completed){
            ERR_OUT("Request not complted:\t0x" << hex << i->addr);
        }

    }

    cout << "Stats verified!" << endl;


}


void some_object::test_single(MultiChannelMemorySystem *mem){

    bool is_write = false;
    uint64_t addr = 0x300000UL;

    unsigned cycles = 4000;

    mem->addTransaction(is_write, addr);

    RequestStat stat;
    stat.addr = addr;
    
    stat.requested_cycle = 1;
    stat.finished_cycle =  0;

    sim_stats.push_back(stat);

    mem->update();
    mem->update();
    mem->update();

    mem->addTransaction(is_write, addr);


    stat;
    stat.addr = addr;
    
    stat.requested_cycle = 4;
    stat.finished_cycle =  0;

    sim_stats.push_back(stat);



    for (int i = 0; i < cycles; ++i){
        //capture_stat();
        mem->update();
    }

}


void some_object::test_sequential(MultiChannelMemorySystem *mem, unsigned count, unsigned cycles){

    unsigned current_count = 0, current_cycles = 0;
    uint64_t addr = 0x300000UL;

    bool is_write = false;


    while(current_cycles < cycles){

        current_cycles++;

        if(mem->willAcceptTransaction(addr) && current_count < count ){

            mem->addTransaction(is_write, addr);

            RequestStat stat;
            stat.addr = addr;
            
            stat.requested_cycle = current_cycles;
            stat.finished_cycle =  0;

            current_count++;

            sim_stats.push_back(stat);

        }

        //capture_stat();
        mem->update();

        addr = addr + 64;

    }


}

void some_object::test_rand(MultiChannelMemorySystem *mem, unsigned count, unsigned cycles){

    unsigned current_count = 0, current_cycles = 0;
    uint64_t addr;

    bool is_write = false;


    while(current_cycles < cycles){

        current_cycles++;

        addr = random() % 0x200000000L;
        addr = addr & ~0x3f; //align to 64B

        is_write = ( random() % 2 == 0 );

        if(mem->willAcceptTransaction(addr) && current_count < count ){

            mem->addTransaction(is_write, addr);

            RequestStat stat;
            stat.addr = addr;
            
            stat.requested_cycle = current_cycles;
            stat.finished_cycle =  0;

            current_count++;

            sim_stats.push_back(stat);

        }

        mem->update();
        //capture_stat();

        

        

    }

    

}




some_object* create_new_sys(){
    some_object *obj = new some_object();

    //todo: delte these objects in destructor
    TransactionCompleteCB *read_cb = new Callback<some_object, void, unsigned, uint64_t, uint64_t>(obj, &some_object::read_complete);
    TransactionCompleteCB *write_cb = new Callback<some_object, void, unsigned, uint64_t, uint64_t>(obj, &some_object::write_complete);

    obj->mem = getMemorySystemInstance("ini/DDR3_micron_64M_8B_x4_sg15.ini", "system.ini", "..", "example_app", 16384);     

    obj->mem->RegisterCallbacks(read_cb, write_cb, power_callback);
    obj->mem->setCPUClockSpeed(3.2e9);
   



    return obj;

}


int main()
{
    

    unsigned req_count = 1e5;
    unsigned sim_cycles = 1000*req_count; //allow 2K cycles per request which is too much.
    

    some_object *obj;
    
    if(TEST_SINGLE){
        //test read from a single address
        cout << "\n*********************************TEST SINGLE******************************************" << endl;
        
        obj = create_new_sys();
        //obj->mem->RegisterCallbacks(read_cb, write_cb, power_callback);

        //obj->test_sequential(obj->mem, 1, 600 );
        obj->test_single(obj->mem);
        obj->check_stats();
        delete obj;
    }

    if(TEST_SEQ){

        cout << "\n*********************************TEST Seq******************************************" << endl;
        obj = create_new_sys();

        
        obj->test_sequential(obj->mem, req_count, sim_cycles );
        obj->check_stats();

        delete obj;
    }

    if(TEST_RAND){
        cout << "\n*********************************TEST Rand******************************************" << endl;
        obj = create_new_sys();
        //obj->mem->RegisterCallbacks(read_cb, write_cb, power_callback);
        

        obj->test_rand(obj->mem, req_count, sim_cycles );
        obj->check_stats();


        delete obj;
    }


    return 0; 
}

