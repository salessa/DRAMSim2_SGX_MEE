

#ifndef PIPELINE_H
#define PIPELINE_H

#include <stdint.h>

template<class T> 
class Pipeline{
	
public:
	Pipeline(uint64_t);
	T tick();
	void add_input(T);
	//bool is_ready();

private:
	int num_stages;
	T* stage;
	T input;
	
};


#endif