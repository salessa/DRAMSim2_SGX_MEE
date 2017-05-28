/*********************************************************************************
*  Copyright (c) 2010-2011, Elliott Cooper-Balis
*                             Paul Rosenfeld
*                             Bruce Jacob
*                             University of Maryland 
*                             dramninjas [at] gmail [dot] com
*  All rights reserved.
*  
*  Redistribution and use in source and binary forms, with or without
*  modification, are permitted provided that the following conditions are met:
*  
*     * Redistributions of source code must retain the above copyright notice,
*        this list of conditions and the following disclaimer.
*  
*     * Redistributions in binary form must reproduce the above copyright notice,
*        this list of conditions and the following disclaimer in the documentation
*        and/or other materials provided with the distribution.
*  
*  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
*  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
*  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
*  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
*  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
*  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
*  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
*  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
*  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
*  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*********************************************************************************/




#include <string>
#include <stdint.h>
#include <DRAMSim.h>
#include <vector>
#include <iostream>

using namespace std;

using namespace DRAMSim;


class some_object
{
	public: 
        some_object(){
            stat_new = false;
        }
        ~some_object(){
            delete mem;
        }

		void read_complete(unsigned, uint64_t, uint64_t);
		void write_complete(unsigned, uint64_t, uint64_t);

        bool stat_new;
        unsigned stat_cycle;
        unsigned stat_address;
        bool stat_is_write;

        MultiChannelMemorySystem *mem;

        struct RequestStat
        {

            unsigned addr;
            bool is_write;
            
            unsigned requested_cycle; 
            unsigned finished_cycle;

        };


        vector<RequestStat> sim_stats;


        void test_single(MultiChannelMemorySystem *mem);
        void test_sequential(MultiChannelMemorySystem *mem, unsigned count, unsigned cycles);
        void test_rand(MultiChannelMemorySystem *mem, unsigned count, unsigned  cycles);
        void capture_stat();
        void check_stats();
        string dump_and_clear();
        unsigned current_cycles = 0;
        unsigned stalled_cycles = 0;

};
