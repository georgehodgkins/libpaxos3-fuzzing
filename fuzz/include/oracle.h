#pragma once

#include "evpaxos.h"

struct oracle_s;
typedef struct oracle_s oracle;

oracle* init_oracle (struct evpaxos_config*, unsigned, int);
void free_oracle (oracle*);
void* oracle_dispatch_thrd (void*);

