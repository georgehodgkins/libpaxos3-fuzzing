#pragma once
#include "paxos.h"
#include "oracle.h"
#include <stdint.h>

typedef enum {
	BSAF_UNIFIED = 7,
	BSAF_PERMSG = 6,
	BSAF_PERNODE_SENDER = 5,
	BSAF_PERNODE_RECIEVER = 4,
	BSAF_PERNET = 3,
	BSAF_PERSIZE = 2,
	FIXED_PERNODE = 1,
	NONE = 0 
} delay_policy_t;


typedef void (*inject_delay_t)(int, int, oracle_message*);


void start_gremlin (const char* config, int osock, atomic_bool* nohup);
