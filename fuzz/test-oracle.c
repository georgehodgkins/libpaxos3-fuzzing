#include "oracle.h"
#include "gremlin.h"
#include <unistd.h> 
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <fcntl.h>

#define EV_CONF_FILE "../../paxos.conf"
#define FUZZ_CONF_FILE "fuzz.conf"
#define PRELOAD_LIB "libfuzzing.so"

#define ACCEPTOR "../sample/acceptor"
#define PROPOSER "../sample/proposer"
#define LEARNER "../sample/learner"
#define CLIENT "../sample/client"

int main () {

	atomic_bool nohup;
	atomic_init(&nohup, true);

	struct evpaxos_config* conf = evpaxos_config_read(EV_CONF_FILE); 
	oracle* O = init_oracle(conf, 32, &nohup);
	int osock = oracle_getsock(O);
	start_gremlin (FUZZ_CONF_FILE, osock, &nohup);

	setenv("LD_PRELOAD", PRELOAD_LIB, 1);

	// spawn other nodes
	int null_fd = open("/dev/null", 0);
	if (fork() == 0) {
		dup2(1, null_fd);
		dup2(2, null_fd);
		execl(ACCEPTOR, ACCEPTOR, "0", EV_CONF_FILE, (char*) 0);
	}
	if (fork() == 0) {
		dup2(1, null_fd);
		dup2(2, null_fd);
		execl(ACCEPTOR, ACCEPTOR, "1", EV_CONF_FILE, (char*) 0);
	}
	if (fork() == 0) {
		dup2(1, null_fd);
		dup2(2, null_fd);
		execl(PROPOSER, PROPOSER, "0", EV_CONF_FILE, (char*) 0);
	}
	if (fork() == 0) {
		dup2(1, null_fd);
		dup2(2, null_fd);
		execl(LEARNER, LEARNER, EV_CONF_FILE, (char*) 0);
	}
	if (fork() == 0) {
		execl(CLIENT, CLIENT, EV_CONF_FILE, "-p", "1", (char*) 0);
	}
	close(null_fd);

	oracle_thread(O);
	free_oracle(O);
	return 0;
}

