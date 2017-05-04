
#ifndef SEQ_SCHED_H
#define SEQ_SCHED_H


#include <unordered_map>
#include <stdint.h>
using namespace std;

class SequentialScheduler{

//TODO: put int config header
#define ACCEL_WRITE_QUEUE 8
#define PIPELINE_STAGES 10

public:
    uint64_t dispatch_event(uint64_t);
    uint64_t current_event(uint64_t);
    void remove_event(uint64_t);
    bool is_event_ready(uint64_t);
    void add_event(uint64_t, uint64_t);


private:

    unordered_map<uint64_t, uint64_t> scheduled_response;    


};


#endif