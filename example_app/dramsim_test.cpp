


#include <stdio.h>
#include "dramsim_test.h"
#include <cassert>
#include <cstdlib>


#define ERR_OUT(str)  std::cerr<< "\033[31m" << str <<endl << "\033[0m" << dec;


#define REQ_CONT 2
#define MIN_REQ_INTERVAL 1

#define TEST_SINGLE false
#define TEST_SEQ false
#define TEST_RAND true



uint64_t total_latency;

/* callback functors */
void some_object::read_complete(unsigned id, uint64_t address, uint64_t clock_cycle)
{
    printf("[Callback] read complete: %d 0x%lx cycle=%lu\n", id, address, clock_cycle);
    assert(!stat_new && "Previous Stat Not Cleared");

    stat_new = true;
    stat_address = address;
    stat_cycle = current_cycles;
    stat_is_write = false;

    capture_stat();

}

void some_object::write_complete(unsigned id, uint64_t address, uint64_t clock_cycle)
{
    printf("[Callback] write complete: %d 0x%lx cycle=%lu\n", id, address, clock_cycle);

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
            total_latency += i->finished_cycle - i->requested_cycle;
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
        char type = i->is_write ? 'w' : 'r';

        if(!completed){
            ERR_OUT("Request not complted:\t0x" << hex << i->addr << "\t" << type);
        }

    }

    cout << "Stats verified!" << endl;


}


void some_object::test_single(MultiChannelMemorySystem *mem){

    bool is_write = false;
    uint64_t addr = 0x327b23c0; //0x300000UL;

    unsigned cycles = 4000;

    assert(mem->addTransaction(is_write, addr) && "ADD Failed");

    RequestStat stat;
    stat.addr = addr;
    
    stat.requested_cycle = 1;
    stat.finished_cycle =  0;

    sim_stats.push_back(stat);

    mem->update();
    mem->update();
    mem->update();

    // mem->addTransaction(is_write, addr);


    // stat;
    // stat.addr = addr;
    
    // stat.requested_cycle = 4;
    // stat.finished_cycle =  0;

    // sim_stats.push_back(stat);



    for (int i = 0; i < cycles; ++i){
        //capture_stat();
        mem->update();
    }

}


void some_object::test_sequential(MultiChannelMemorySystem *mem, unsigned count, unsigned cycles){

    unsigned current_count = 0;
    uint64_t addr = 0x300000UL;
    unsigned ready_cycle = 0;

    bool is_write = false;
    unsigned last_req_cycle=0;

    while(current_cycles < cycles ){

        current_cycles++;

        if(mem->willAcceptTransaction(addr) && current_count < count &&
            last_req_cycle + MIN_REQ_INTERVAL <= current_cycles  ){

            assert(mem->addTransaction(is_write, addr) && "Add failed");

            last_req_cycle = current_cycles;

            RequestStat stat;
            stat.addr = addr;
            
            stat.requested_cycle = current_cycles;
            cout << "requested @ cycle\t" << current_cycles << endl;
            stat.finished_cycle =  0;
            stat.is_write = is_write;


            current_count++;

            sim_stats.push_back(stat);

            addr = addr + 64;

        }
        else{
            if(current_count < REQ_CONT) stalled_cycles++;
        }

        //capture_stat();
        mem->update();

    }

    assert(current_count == REQ_CONT);


}

void some_object::test_rand(MultiChannelMemorySystem *mem, unsigned count, unsigned cycles){

    unsigned current_count = 0;

    uint64_t addr;

    bool is_write = false;

    unsigned last_req_cycle = 0;

    while(current_cycles < cycles){

        current_cycles++;

        addr = random() % 0x200000000L;
        addr = addr & ~0x3f; //align to 64B

        is_write = ( random() % 2 == 0 );

        if(mem->willAcceptTransaction(addr) && current_count < count && 
           last_req_cycle + MIN_REQ_INTERVAL <= current_cycles ){

            assert(mem->addTransaction(is_write, addr) && "ADD failed");
            last_req_cycle = current_cycles;

            RequestStat stat;
            stat.addr = addr;
            
            stat.requested_cycle = current_cycles;
            stat.finished_cycle =  0;

            stat.is_write = is_write;

            current_count++;

            sim_stats.push_back(stat);

        }

        mem->update();
        //capture_stat();

        

        

    }

    assert(current_count == count);

    

}




some_object* create_new_sys(){
    some_object *obj = new some_object();

    //todo: delte these objects in destructor
    TransactionCompleteCB *read_cb = new Callback<some_object, void, unsigned, uint64_t, uint64_t>(obj, &some_object::read_complete);
    TransactionCompleteCB *write_cb = new Callback<some_object, void, unsigned, uint64_t, uint64_t>(obj, &some_object::write_complete);

    obj->mem = getMemorySystemInstance("ini/DDR3_micron_32M_8B_x4_sg125.ini", "system.ini", "..", "example_app", 16384);     

    obj->mem->RegisterCallbacks(read_cb, write_cb, power_callback);
    obj->mem->setCPUClockSpeed(3.2e9);
   



    return obj;

}


int main()
{
    

    
    unsigned sim_cycles = 4000*REQ_CONT; //allow 1K cycles per request which is too much.
    

    some_object *obj;
    
    if(TEST_SINGLE){
        //test read from a single address
        cout << "\n*********************************TEST SINGLE******************************************" << endl;
        
        obj = create_new_sys();
        //obj->mem->RegisterCallbacks(read_cb, write_cb, power_callback);

        //obj->test_sequential(obj->mem, 1, 600 );
        obj->test_single(obj->mem);
        obj->check_stats();
        cout << "Stalled Cycles:\t" << obj->stalled_cycles << endl;

        delete obj;
    }

    if(TEST_SEQ){

        cout << "\n*********************************TEST Seq******************************************" << endl;
        obj = create_new_sys();

        
        obj->test_sequential(obj->mem, REQ_CONT, sim_cycles );
        obj->check_stats();
        
        cout << "Stalled Cycles:\t" << obj->stalled_cycles << endl;


        delete obj;

        cout << "Average Latency SEQ: "  << "\t" << total_latency/REQ_CONT << endl;
    }

    if(TEST_RAND){
        cout << "\n*********************************TEST Rand******************************************" << endl;
        obj = create_new_sys();
        //obj->mem->RegisterCallbacks(read_cb, write_cb, power_callback);
        

        obj->test_rand(obj->mem, REQ_CONT, sim_cycles );
        obj->check_stats();

        cout << "Stalled Cycles:\t" << obj->stalled_cycles << endl;


        cout << "Average Latency RAND: " << total_latency/REQ_CONT << endl;
    }








    return 0; 
}

