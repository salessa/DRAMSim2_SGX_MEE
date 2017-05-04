#ifndef UTIL_H
#define UTIL_H

#include<iostream>
using namespace std;

#ifdef DEBUG_MEE
	#define MEE_DEBUG(str)  std::cerr<< current_cycle << "\t" << str <<endl << dec;
	#define MEE_DEBUGN(str) std::cerr<< current_cycle << "\t" << str << dec;
#else
	#define MEE_DEBUG(str) ;
	#define MEE_DEBUGN(str) ;
#endif


#endif