

#ifndef SIM_OBJ_H
#define SIM_OBJ_H

#include <cstdint>

//template<typename T_I, typename T_O> 
class SimObject{

public:

	SimObject(){ current_cycle = 0;}
    
    virtual void tick() = 0;
    virtual bool exit_sim(){ return false; }
    /*
    virtual bool can_accept_input() {return true;}    
    virtual void add_input(T_I input);
    virtual bool is_output_ready(){return false;}
    virtual T_O get_output();
    */
    uint64_t current_cycle;

};



#endif
