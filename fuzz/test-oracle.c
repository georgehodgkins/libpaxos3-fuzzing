#include "oracle.h"
#include <unistd.h> 

#define CONF_FILE "../../paxos.conf"

#define ACCEPTOR "../sample/acceptor"
#define PROPOSER "../sample/proposer"
#define LEARNER "../sample/learner"
#define CLIENT "../sample/client"

int main () {
	
	struct evpaxos_config* conf = evpaxos_config_read(CONF_FILE); 
	oracle* O = init_oracle(conf, 64, 5551);

	// spawn other nodes
	int null_fd = open("/dev/null", 0);
	if (fork() == 0) {
		dup2(null_fd, stdout);
		dup2(null_fd, stderr);
		execl(ACCEPTOR, ACCEPTOR, "0", CONF_FILE, (char*) 0);
	}
	if (fork() == 0) {
		dup2(null_fd, stdout);
		dup2(null_fd, stderr);
		execl(ACCEPTOR, ACCEPTOR, "1", CONF_FILE, (char*) 0);
	}
	if (fork() == 0) {
		dup2(null_fd, stdout);
		dup2(null_fd, stderr);
		execl(PROPOSER, PROPOSER, "0", CONF_FILE, (char*) 0);
	}
	if (fork() == 0) {
		dup2(null_fd, stdout);
		dup2(null_fd, stderr);
		execl(LEARNER, LEARNER, CONF_FILE, (char*) 0);
	}
	if (fork() == 0) {
		execl(CLIENT, CLIENT, CONF_FILE, "-p", "1", (char*) 0);
	}
	close(null_fd);

	oracle_dispatch_thrd(O);
	free_oracle(O);
	return 0;
}

