#pragma once
#include "paxos.h"
#include "oracle.h"
#include <stdint.h>
#include <stdbool.h>

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

typedef enum {
	NODE_NONE = 0,
	NODE_PROPOSER = 1,
	NODE_ACCEPTOR = 2,
	NODE_CLIENT = 3
} node_type_t;

typedef void (*inject_delay_t)(int, int, oracle_message*);

extern const size_t policy_reqd_size[];

void start_delay_gremlin (const char* config, int osock, atomic_bool* nohup);

const char* start_node_gremlin(unsigned maxnode);

atomic_bool* gremlin_get_nohup();

void gremlin_add_node(node_type_t type);

void gremlin_kill_node(unsigned id);

void free_node_gremlin();
void free_delay_gremlin();

