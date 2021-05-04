#include "oracle.h"
#include "gremlin.h"
#include <unistd.h> 
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <fcntl.h>

#define FUZZ_FILE "vector.fuzz"
#define PRELOAD_LIB "libfuzzing.so"
#define MAXNODE 4

int main () {

	const char* tmp_conf_path = start_node_gremlin(MAXNODE);
	struct evpaxos_config* conf = evpaxos_config_read(tmp_conf_path); 
	atomic_bool* nohup = gremlin_get_nohup();
	oracle* O = init_oracle(conf, 32, nohup);
	int osock = oracle_getsock(O);
	start_delay_gremlin (FUZZ_FILE, osock, nohup);

	char* full_preload_path = realpath(PRELOAD_LIB, NULL);
	if (!full_preload_path) {
		perror("realpath");
		abort();
	}
	int s = setenv("LD_PRELOAD", full_preload_path, 1);
	if (s == -1) {
		perror("setenv");
		abort();
	}
	free(full_preload_path);

	// spawn nodes
	gremlin_add_node(NODE_PROPOSER);
	gremlin_add_node(NODE_ACCEPTOR);
	gremlin_add_node(NODE_ACCEPTOR);
	gremlin_add_node(NODE_CLIENT);

	oracle_thread(O);
	free_oracle(O);
	free_delay_gremlin();
	free_node_gremlin();
	return 0;
}

