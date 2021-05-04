#include "gremlin.h"
#include <stdatomic.h>
#include <sys/types.h>
#include <stdio.h>
#define _GNU_SOURCE
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#define MAX_MAX_NODE 1000
#define PROPOSER_PATH "../sample/proposer"
#define ACCEPTOR_PATH "../sample/acceptor"
#define CLIENT_PATH "../sample/client"

typedef void (*invoke_node_t) (const char*, const char*);

__attribute__((noreturn))
static void invoke_proposer (const char* idbuf, const char* conf) {
	int null_fd = open("/dev/null", O_RDWR);
	dup2(1, null_fd);
	dup2(2, null_fd);
	execl(PROPOSER_PATH, PROPOSER_PATH, idbuf, conf, (char*) 0);
}

__attribute__((noreturn))
static void invoke_acceptor (const char* idbuf, const char* conf) {
	int null_fd = open("/dev/null", O_RDWR);
	dup2(1, null_fd);
	dup2(2, null_fd);
	execl(ACCEPTOR_PATH, ACCEPTOR_PATH, idbuf, conf, (char*) 0);
}

__attribute__((noreturn))
static void invoke_client (const char* idbuf, const char* conf) {
	execl(CLIENT_PATH, CLIENT_PATH, conf, (char*) 0);
}

invoke_node_t invoke_node[] = {
	NULL,
	&invoke_proposer,
	&invoke_acceptor,
	&invoke_client
};

struct node_gremlin {
	pid_t* children;
	node_type_t* child_type;
	unsigned child_count;
	unsigned loid;
	unsigned hiid;
	unsigned maxnode;
	const char* conf;
	atomic_bool nohup;
} nodectl;

void gremlin_normal_exit () {
	atomic_store(&nodectl.nohup, false);
	kill(0, SIGINT); // send to whole process group
}

void gremlin_error_exit () {
	atomic_store(&nodectl.nohup, false);
	kill(0, SIGTERM);
}

atomic_bool* gremlin_get_nohup () {
	return &nodectl.nohup;
}

// in addition to abnormal termination,
// SIGCHLD is also delivered by the gremlin when the full delay sequence
// has been consumed -- i.e. normal termination
void handle_sigchld (int signum, siginfo_t* info, void* ctx) {
	assert(signum == SIGCHLD);
	
	// avoid terminating when the fuzzer kills a node on purpose
	bool ownkill = true;
	for (unsigned i = 0; i < nodectl.hiid; ++i) {
		if (nodectl.children[i] == info->si_pid) {
			ownkill = false;
			break;
		}
	}
	
	if (!ownkill) {
		atomic_store(&nodectl.nohup, false);
		if (info->si_code == SI_QUEUE) {
			gremlin_normal_exit(); 
		} else {
			assert(info->si_code == CLD_EXITED);
			gremlin_error_exit();
		}
	}
}

static char mtmpnam[32];

const char* start_node_gremlin (unsigned maxnode) {
	assert(maxnode < MAX_MAX_NODE);
	nodectl.children = calloc(maxnode, sizeof(pid_t));
	nodectl.child_type = calloc(maxnode, sizeof(node_type_t));
	
	atomic_init(&nodectl.nohup, true);
	nodectl.child_count = 0;
	nodectl.loid = 0;
	nodectl.hiid = 0;

	struct sigaction sa = {
		.sa_sigaction = handle_sigchld,
		.sa_flags = SA_NOCLDSTOP | SA_SIGINFO
	};
	int s = sigaction(SIGCHLD, &sa, NULL);

	strcpy(mtmpnam, "/tmp/paxfuzzconfXXXXXX");
	int fd = mkstemp(mtmpnam);
	if (fd == -1) {
		perror("mkstemp");
		abort();
	}
	nodectl.conf = mtmpnam;

	FILE* txtfd = fdopen(fd, "w");
	fprintf(txtfd, "# Auto-generated paxos.conf from fuzzer\n");
	for (unsigned i = 0; i < maxnode; ++i) {
		fprintf(txtfd, "replica %u 127.0.0.1 %u\n", i, 8800 + i);
	}
	fclose(txtfd);
	
	return mtmpnam;
}

void free_node_gremlin () {
	free(nodectl.children);
	free(nodectl.child_type);
	unlink(nodectl.conf);
}

void gremlin_add_node(node_type_t type) {
	assert(type != NODE_NONE);

	unsigned id = nodectl.loid;
	while (++(nodectl.loid) < nodectl.maxnode && nodectl.children[nodectl.loid]) {}
	if (id >= nodectl.hiid) nodectl.hiid = id+1; 
	++nodectl.child_count;

	char idbuf[4];
	snprintf(idbuf, 4, "%u", id);
	pid_t parent_grp = getpgrp(); 

	pid_t c = fork();
	if (c == 0) {
		setpgid(0, parent_grp);
		invoke_node[type](idbuf, nodectl.conf);
		abort(); // unreachable unless exec fails
	} else {
		nodectl.children[id] = c;
	}
}

void gremlin_kill_node(unsigned id) {
	// temporarily mask SIGCHLD so we can register the kill before the signal handler fires
	sigset_t s;
	sigemptyset(&s);
	sigaddset(&s, SIGCHLD);

	sigprocmask(SIG_BLOCK, &s, NULL);

	kill(nodectl.children[id], SIGKILL);

	nodectl.children[id] = (pid_t) 0;
	nodectl.child_type[id] = NODE_NONE;
	--nodectl.child_count;

	if (id < nodectl.loid) nodectl.loid = id;
	if (id+1 == nodectl.hiid) {
		while (--(nodectl.hiid) && !nodectl.children[nodectl.hiid]) {}
	}

	sigprocmask(SIG_UNBLOCK, &s, NULL);
}

// TODO: gremlin_pause_node
