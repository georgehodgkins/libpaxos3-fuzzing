#pragma once

#include "evpaxos.h"
#include <stdatomic.h>

struct oracle_s;
typedef struct oracle_s oracle;

struct oracle_message {
	uint64_t ts;
	paxos_message paxmsg;
};
typedef struct oracle_message oracle_message;

oracle* init_oracle (struct evpaxos_config*, unsigned, atomic_bool*);
void free_oracle (oracle*);
void* oracle_thread (void*);
void oracle_dispatch(oracle*);
int oracle_getsock(oracle*);

#define ORACLE_SOCK_PATH "/tmp/fuzz_oraclesock"

