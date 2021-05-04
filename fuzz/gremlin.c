#include <stdatomic.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <string.h>
#include <pthread.h>
#define __USE_GNU
#define _GNU_SOURCE
#include <dlfcn.h>
#include <event.h>
#include <event2/event.h>

#include "gremlin.h"

#define RAND_STATE_SIZE 32
#define GREMLIN_CTL_PATH "/fuzz_gremlin_ctl"

/*-----File-scope globals-----*/
// These are not shared between different gremlin instances and/or the master process
static int ctl_fd; // shm fd for gremlin control
static struct gremlin_ctl* gremlin; // parsed gremlin control struct in shm
static pthread_attr_t async_attr; // attributes for async threads


/*-----Delay policies-----*/
// Various ways to specify message delays deterministically
// from a stream of arbitrary bytes
typedef struct {
	uint16_t factor;
} bsaf_single_param;

typedef struct {
	uint16_t prep_factor;
	uint16_t prom_factor;
	uint16_t prop_factor;
	uint16_t acc_factor;
	uint16_t accd_factor;
	uint16_t cval_factor;
	// we don't capture these message types
	// but we still inject delay for them
	uint16_t preem_factor;
	uint16_t rep_factor;
	uint16_t trim_factor;
	uint16_t acst_factor;
} bsaf_permsg_param;

typedef struct {
	uint16_t prop_factor;
	uint16_t acc_factor;
	uint16_t cli_factor;
} bsaf_pernode_param;

typedef struct {
	uint16_t int_factor;
	uint16_t ext_factor;
} bsaf_pernet_param;

/*-----Gremlin struct def-----*/
typedef struct gremlin_ctl {
	atomic_bool* nohup;
	delay_policy_t dpol;
	inject_delay_t inject_delay;
	int wsock_fd; // socket to send messages to oracle
	int rfifo_fd; // fifo to get delay bytes
	unsigned int RS;
	char* RF;
	union {
		bsaf_single_param single;
		bsaf_permsg_param permsg;
		bsaf_pernode_param pernode;
		bsaf_pernet_param pernet;
	} param;
} gremlin_ctl;

// helper fn to get a byte off the FIFO
static uint8_t inj_getb(int fifo_fd) {
	uint8_t nxt;
	int s = read(fifo_fd, &nxt, 1);
	if (s == -1) {
		perror("delay fifo read");
		abort();
	}
	return nxt;
}

// constructors for policy objects held in union
void parse_single_param(int fd, gremlin_ctl* ctl) {
	int s = read(fd, &ctl->param.single.factor, 2);
	assert(s == 2);
}

void parse_permsg_param(int fd, gremlin_ctl* ctl) {
	int s = read(fd, &ctl->param.permsg.prep_factor, 2);
	assert(s == 2);
	s = read(fd, &ctl->param.permsg.prom_factor, 2);
	assert(s == 2);
	s = read(fd, &ctl->param.permsg.prop_factor, 2);
	assert(s == 2);
	s = read(fd, &ctl->param.permsg.acc_factor, 2);
	assert(s == 2);
	s = read(fd, &ctl->param.permsg.accd_factor, 2);
	assert(s == 2);
	s = read(fd, &ctl->param.permsg.cval_factor, 2);
	assert(s == 2);
	s = read(fd, &ctl->param.permsg.preem_factor, 2);
	assert(s == 2);
	s = read(fd, &ctl->param.permsg.rep_factor, 2);
	assert(s == 2);
	s = read(fd, &ctl->param.permsg.trim_factor, 2);
	assert(s == 2);
	s = read(fd, &ctl->param.permsg.acst_factor, 2);
	assert(s == 2);
}

void parse_pernode_param(int fd, gremlin_ctl* ctl) {
	int s = read(fd, &ctl->param.pernode.prop_factor, 2);
	assert(s == 2);
	s = read(fd, &ctl->param.pernode.acc_factor, 2);
	assert(s == 2);
	s = read(fd, &ctl->param.pernode.cli_factor, 2);
	assert(s == 2);
}

void parse_pernet_param(int fd, gremlin_ctl *ctl) {
	int s = read(fd, &ctl->param.pernet.int_factor, 2);
	assert(s == 2);
	s = read(fd, &ctl->param.pernet.ext_factor, 2);
	assert(s == 2);
}

typedef void (*policy_parse_t)(int, gremlin_ctl*);

// single factor for all messages
static void inject_bsaf_unified(int fifo_fd, int rd, oracle_message* msg) {
	uint8_t nxt = inj_getb(fifo_fd);
	struct timespec ts = {0, rd};
	ts.tv_nsec += (1000 * gremlin->param.single.factor * (uint32_t) nxt) / 0xff; 
	nanosleep(&ts, NULL);
}

// different factors based on message type
static void inject_bsaf_permsg(int fifo_fd, int rd, oracle_message* msg) {
	uint8_t nxt = inj_getb(fifo_fd);
	struct timespec ts = {0, rd};
	uint16_t factor;
	switch (msg->paxmsg.type) {
	case PAXOS_PREPARE:
		factor = gremlin->param.permsg.prep_factor;
		break;
	case PAXOS_PROMISE:
		factor = gremlin->param.permsg.prom_factor;
		break;
	case PAXOS_ACCEPT:
		factor = gremlin->param.permsg.acc_factor;
		break;
	case PAXOS_ACCEPTED:
		factor = gremlin->param.permsg.accd_factor;
		break;
	case PAXOS_PREEMPTED:
		factor = gremlin->param.permsg.preem_factor;
		break;
	case PAXOS_REPEAT:
		factor = gremlin->param.permsg.rep_factor;
		break;
	case PAXOS_TRIM:
		factor = gremlin->param.permsg.trim_factor;
		break;
	case PAXOS_ACCEPTOR_STATE:
		factor = gremlin->param.permsg.acst_factor;
		break;
	case PAXOS_CLIENT_VALUE:
		factor = gremlin->param.permsg.cval_factor;
	}
	ts.tv_nsec += (1000 * factor * (uint32_t) nxt) / 0xff; 
	nanosleep(&ts, NULL);
}

// different factors based on message sender
static void inject_bsaf_pernode_sender(int fifo_fd, int rd, oracle_message* msg) {
	uint8_t nxt = inj_getb(fifo_fd);
	struct timespec ts = {0, rd};
	uint16_t factor;
	switch (msg->paxmsg.type) {
		// sent by proposer
		case PAXOS_PREPARE:
		case PAXOS_ACCEPT: 
		case PAXOS_REPEAT:
		case PAXOS_TRIM:
			factor = gremlin->param.pernode.prop_factor;
			break;
		// sent by acceptor
		case PAXOS_PROMISE:
		case PAXOS_ACCEPTED:
		case PAXOS_ACCEPTOR_STATE:
		case PAXOS_PREEMPTED:
			factor = gremlin->param.pernode.acc_factor;
			break;
		// sent by client
		case PAXOS_CLIENT_VALUE:
			factor = gremlin->param.pernode.cli_factor;
	}
	ts.tv_nsec += (1000 * factor * (uint32_t) nxt) / 0xff; 
	nanosleep(&ts, NULL);
}

// different factors based on message reciever
static void inject_bsaf_pernode_reciever(int fifo_fd, int rd, oracle_message* msg) {
	uint8_t nxt = inj_getb(fifo_fd);
	struct timespec ts = {0, rd};
	uint16_t factor;
	switch (msg->paxmsg.type) {
		// recieved by acceptor
		case PAXOS_PREPARE:
		case PAXOS_ACCEPT: 
		case PAXOS_REPEAT:
		case PAXOS_TRIM:
			factor = gremlin->param.pernode.acc_factor;
			break;
		// recieved by proposer
		case PAXOS_PROMISE:
		case PAXOS_ACCEPTED:
		case PAXOS_ACCEPTOR_STATE:
		case PAXOS_PREEMPTED:
		case PAXOS_CLIENT_VALUE:
			factor = gremlin->param.pernode.prop_factor;
			break;
		// nobody sends the client anything :(
	}
	ts.tv_nsec += (1000 * factor * (uint32_t) nxt) / 0xff; 
	nanosleep(&ts, NULL);
}

// factors based on whether the message involved a client
static void inject_bsaf_pernet(int fifo_fd, int rd, oracle_message* msg) {
	uint8_t nxt = inj_getb(fifo_fd);
	struct timespec ts = {0, rd};
	uint16_t factor;
	switch (msg->paxmsg.type) {
		// internal message
		case PAXOS_PREPARE:
		case PAXOS_ACCEPT: 
		case PAXOS_REPEAT:
		case PAXOS_TRIM:
		case PAXOS_PROMISE:
		case PAXOS_ACCEPTED:
		case PAXOS_ACCEPTOR_STATE:
		case PAXOS_PREEMPTED:
			factor = gremlin->param.pernet.int_factor;
			break;
		case PAXOS_CLIENT_VALUE:
			factor = gremlin->param.pernet.ext_factor;
			break;
	}
	ts.tv_nsec += (1000 * factor * (uint32_t) nxt) / 0xff; 
	nanosleep(&ts, NULL);
}

static void inject_fixed_pernode(int fifo_fd, int rd, oracle_message* msg) {
	// get a factor once per node instance
	static uint8_t instat = 0;
	if (instat == 0) instat = inj_getb(fifo_fd);
	struct timespec ts = {0, rd + instat*gremlin->param.single.factor};
	nanosleep(&ts, NULL);
}

static void inject_none (int fifo_fd, int rd, oracle_message* msg) {
	struct timespec ts = {0, rd};
	if (ts.tv_nsec) nanosleep(&ts, NULL);
}

static const inject_delay_t delay_injector[] = {
	&inject_none,
	&inject_fixed_pernode,
	&inject_bsaf_pernet,
	&inject_bsaf_pernode_reciever,
	&inject_bsaf_pernode_sender,
	&inject_bsaf_permsg,
	&inject_bsaf_unified
};

static const size_t policy_reqd_size[] = {
	0,
	sizeof(bsaf_single_param),
	sizeof(bsaf_pernet_param),
	sizeof(bsaf_pernode_param),
	sizeof(bsaf_pernode_param),
	sizeof(bsaf_permsg_param),
	sizeof(bsaf_single_param)
};

static const policy_parse_t policy_parser[] = {
	NULL,
	&parse_single_param,
	&parse_pernet_param,
	&parse_pernode_param,
	&parse_pernode_param,
	&parse_permsg_param,
	&parse_single_param
};

static const size_t rf_reqd_size = sizeof(unsigned int);


/*-----Delay pusher thread-----*/
typedef struct delay_pusher_args {
	uint8_t* loop;
	size_t loop_len;
	int wfifo_fd;
} delay_pusher_args;

void* delay_pusher_thread (void* arg_v) {
	delay_pusher_args* arg = arg_v;
	while (atomic_load(gremlin->nohup)) {
		int s = write(arg->wfifo_fd, arg->loop, arg->loop_len);
		assert(s == arg->loop_len);
	}

	close(arg->wfifo_fd);
	free(arg->loop);
	free(arg);
	return NULL;
}

/*-----Setup functions-----*/
static void gremlin_dispatch (const char* config, gremlin_ctl* ctl) {
	int fd = open(config, O_CLOEXEC | O_RDONLY);
	if (fd == -1) {
		perror("gremlin config open");
		abort();
	}
	struct stat st;
	int s = fstat(fd, &st);
	assert(s == 0);
	size_t len = st.st_size;

	// get policy byte
	uint8_t polbyte;
	s = read(fd, &polbyte, 1);
	assert(s == 1);
	delay_policy_t dpol = (delay_policy_t) ((polbyte >> 4) & ~0x8);
	bool RFsel = (bool) polbyte >> 7;
	if (len < 2 + policy_reqd_size[dpol] + (RFsel) ? rf_reqd_size : 0) {
		printf("Input file is too small for this policy selection!");
		abort();
	}
	ctl->dpol = dpol;
	ctl->inject_delay = delay_injector[dpol];

	// setup random state if requested
	if (RFsel) {
		s = read(fd, &ctl->RS, sizeof(unsigned int));
		assert(s == sizeof(unsigned int));
		ctl->RF = malloc(sizeof(uint8_t)*RAND_STATE_SIZE);
		initstate(ctl->RS, ctl->RF, RAND_STATE_SIZE);
		char* r = setstate(ctl->RF);
		assert(r);
	}
	
	// parse parameters according to policy, advancing fd
	if (policy_parser[dpol]) policy_parser[dpol](fd, ctl);

	// copy remaining bytes into array for pusher
	size_t loop_len = len - 2 - policy_reqd_size[dpol] - (RFsel) ? rf_reqd_size : 0;
	uint8_t* loop = malloc(loop_len);
	s = read(fd, loop, loop_len);
	assert(s == loop_len);
	close(fd);

	// launch pusher
	delay_pusher_args* arg = malloc(sizeof(delay_pusher_args));		
	arg->loop = loop;
	arg->loop_len = loop_len;
	int pipefd[2];
	s = pipe(pipefd);
	if (s == -1) {
		perror("gremlin pipe");
		abort();
	}
	arg->wfifo_fd = pipefd[1]; // write end
	ctl->rfifo_fd = pipefd[0]; // read end
	pthread_t thr;
	s = pthread_create(&thr, &async_attr, delay_pusher_thread, arg);
	assert(s == 0);
}


void start_gremlin (const char* config, int osock, atomic_bool* nohup) {
	// set up shm region for inter-process control info
	ctl_fd = shm_open(GREMLIN_CTL_PATH, O_RDWR | O_CREAT | O_EXCL, 0);
	if (ctl_fd == -1) {
		perror("shm_open");
		goto failure_to_launch;
	}
	int s = ftruncate(ctl_fd, sizeof(struct gremlin_ctl));
	if (s == -1) {
		perror("ftruncate");
		goto failure_to_launch;
	}
	gremlin_ctl* ctl = mmap(NULL, sizeof(struct gremlin_ctl), PROT_READ | PROT_WRITE,
			MAP_SHARED, ctl_fd, 0);
	if (ctl == MAP_FAILED) {
		perror("mmap");
		goto failure_to_launch;
	}
	ctl->wsock_fd = osock;
	ctl->nohup = nohup;

	gremlin_dispatch(config, ctl);
	gremlin = ctl;
	return;

failure_to_launch:
	munmap(ctl, sizeof(struct gremlin_ctl));
	close(ctl_fd);
	shm_unlink(GREMLIN_CTL_PATH);
	abort();
}

// dynamically loaded hook to real message send
typedef void (*send_msg_hook)(struct bufferevent*, paxos_message*);
send_msg_hook real_send_paxos_message = NULL;

__attribute__((constructor))
void init_gremlin_process_instance (void) {
	// attach to control shm
	ctl_fd = shm_open(GREMLIN_CTL_PATH, O_RDONLY, 0);
	if (ctl_fd > 0) { // gremlin has been initialized
		gremlin = mmap(NULL, sizeof(struct gremlin_ctl), PROT_READ | PROT_WRITE,
				MAP_SHARED, ctl_fd, 0);

		// find hook
		real_send_paxos_message = (send_msg_hook) dlsym(RTLD_NEXT, "send_paxos_message");
		assert(real_send_paxos_message && "Could not attach message hook!");
	}
	
	// set up delay thread attributes
	pthread_attr_init(&async_attr);
	pthread_attr_setdetachstate(&async_attr, PTHREAD_CREATE_DETACHED);
	pthread_attr_setstacksize(&async_attr, 0x10000); // minimum size

}

__attribute__((destructor))
void close_gremlin_process_instance (void) {
	munmap(gremlin, sizeof(struct gremlin_ctl));
	close(ctl_fd);
}


typedef struct async_sender_args {
	struct bufferevent* bev;
	oracle_message msg;
} async_sender_args;

void gremlin_set_ts (oracle_message* m) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	// in nanoseconds
	m->ts = (uint64_t) ts.tv_sec*1000000000 + ts.tv_nsec;
}

void* async_sender_thread(void* arg_v) {
	async_sender_args* arg = arg_v;
	// inject delay according to control params
	// TODO: random factor
	gremlin->inject_delay(gremlin->rfifo_fd, 0, &arg->msg);
	// send message to oracle
	gremlin_set_ts(&arg->msg);
	write(gremlin->wsock_fd, &arg->msg, sizeof(oracle_message));
	// send message to its intended recipients
	real_send_paxos_message(arg->bev, &arg->msg.paxmsg);

	free(arg);
	return NULL; 
}

// intercepts calls to libpaxos function of the same name
void send_paxos_message(struct bufferevent* bev, paxos_message* msg) {
	async_sender_args* arg = malloc(sizeof(async_sender_args));
	arg->bev = bev;
	memcpy(&arg->msg.paxmsg, msg, sizeof(paxos_message)); 
	pthread_t thr;
	int s = pthread_create(&thr, &async_attr, async_sender_thread, arg);
	assert(s == 0);
}
	
