
#include "mee_sequential_scheduler.h"



void SequentialScheduler::add_event(uint64_t earliest_cycle, 
                                    uint64_t value){
    
    while( scheduled_response.find(earliest_cycle) != 
           scheduled_response.end() ){

            earliest_cycle++;
    }

    scheduled_response[earliest_cycle] = value;
}


bool SequentialScheduler::is_event_ready(uint64_t cycle){
    return scheduled_response.find(cycle) != scheduled_response.end();
}


uint64_t SequentialScheduler::current_event(uint64_t cycle){
    
    uint64_t val = scheduled_response[cycle];
    
    return val;
}


void SequentialScheduler::remove_event(uint64_t cycle){
    scheduled_response.erase(cycle);
}