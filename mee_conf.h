#ifndef MEE_CONF_H
#define MEE_CONF_H

#include <cstdint>
#include <stdlib.h> // getenv()
#include "mee_utils.h"



#define CTR_BITS 56
#define MAC_BITS 64

//this is for the counter cache
#define CACHE_ACCESS_CYCLES 2


#define DECRYPTOR_INPUT_QUEUE 48
#define CACHE_UPDATE_QUEUE 16
#define DRAM_REQ_OUTSTANDING 48 //this does not include request made through caches

#define AES_STAGES 10

//do GF mult + XOR + compare MAC
#define CRYPTO_FINALIZE_CYCLES 2

#define MB 1024*1024

#define MAC_REGION_SIZE 512*MB //512MB covers a 4GB space!
#define VER_REGION_SIZE 512*MB
#define L0_REGION_SIZE  VER_REGION_SIZE/8
#define L1_REGION_SIZE  L0_REGION_SIZE/8 //?
#define L2_REGION_SIZE  L1_REGION_SIZE/8 //?
#define L3_REGION_SIZE  L2_REGION_SIZE/8 //?
#define L4_REGION_SIZE  L3_REGION_SIZE/8 //?
#define L5_REGION_SIZE  L4_REGION_SIZE/8 //?
#define PATCH_REGION_SIZE  MB/16 //?


#define CTR_PER_CL 8
#define MAC_PER_CL 8


//FIXME:
//for our branching scheme, we reserve counter spots to protect the branches.
//so we should re-work the layout so that VER_PER_CL = 4
#ifdef TETRIS
#define VER_PER_CL 8
#else
#define VER_PER_CL 8
#endif



//for now let's use the lowest part of the phycical address 
//for storing meta-data
#define DATA_REGION_START 0
#define MAC_REGION_START 0x800000000000
#define VER_REGION_START MAC_REGION_START + MAC_REGION_SIZE + 64
#define L0_REGION_START  VER_REGION_START + VER_REGION_SIZE + 64
#define L1_REGION_START  L0_REGION_START + L0_REGION_SIZE + 64
#define L2_REGION_START  L1_REGION_START + L1_REGION_SIZE + 64
#define L3_REGION_START  L2_REGION_START + L2_REGION_SIZE + 64
#define L4_REGION_START  L3_REGION_START + L3_REGION_SIZE + 64
#define L5_REGION_START  L4_REGION_START + L4_REGION_SIZE + 64
#define PATCH_REGION_START  L5_REGION_START + L5_REGION_SIZE + 64



//if the CPU simulator does not implement a proper TLB,
//it might send the virtual address. 
//this will be problamatic when computing the address for CTR, MAC etc...
//so we mask it first
#define VIRT_ADDR_MASK 0xffffffff


#define RICE_K 4


#endif
