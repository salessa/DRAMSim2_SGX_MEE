#include "mee_pipeline_simple.h"
#include <cstdlib>

template<class T> 
void Pipeline<T>::add_input(T input){
	this->input = input;
}

template<class T> 
Pipeline<T>::Pipeline(uint64_t pipeline_stages): num_stages(pipeline_stages) { 
	stage = new T[num_stages]; 

	for (int i = 0; i < num_stages; ++i)
	{
		stage[i] = (T)NULL;
	}

}


template<class T> 
T Pipeline<T>::tick(){

	T output = stage[num_stages-1];

	//advance each stage
	for (int i = num_stages-2; i >= 0; --i)
	{
		stage[i+1] = stage[i];	
	}

	//place new input on pipeline
	stage[0] = input;

	//set input to NULL so that the same input is not being held at the input
	input = (T)NULL;	


	return output;


}
