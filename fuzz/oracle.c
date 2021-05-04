#include "paxos.h"
#include "evpaxos.h"
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <signal.h>
#include <poll.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>

#include "oracle.h"

/*----------Oracle struct definition-----------*/

struct oracle_s {
	int isock; // input side of socket pair (given to gremlin)
	int osock; // output side of socket pair (monitored by oracle)
	atomic_bool* nohup; // termination indicator (controlled by node gremlin) 

	unsigned acc_count; // number of acceptors (from paxos conf file)
	unsigned pro_count; // number of proposers 
	// acceptor state
	uint32_t* acc_prombal; // last promised ballot for each acceptor
	uint32_t* acc_accbal; // last accepted ballot for each acceptor
	paxos_value* acc_accval; // last accepted value for each acceptor
	uint32_t* acc_lastbal; // last ballot accepted by acceptor, as marked in Promise 
	paxos_value* acc_lastval; // last value ^^
	uint32_t* acc_sortbal; // acceptors sorted by last accepted ballot (for chking Agreement2)
	// proposer state
	uint32_t* pro_prepbal; // last prepared ballot for each proposer
	uint32_t* pro_propbal; // last proposed ballot for each proposer
	paxos_value* pro_propval; // last proposed value for each proposer
	// proposed value histories (for checking Validity)
	unsigned vhist_cap; // capacity of vhists
	paxos_value* cli_vhist; // history of client sent values
	unsigned cli_vhist_len;
	paxos_value* pro_vhist; // history of proposer proposed values
	unsigned pro_vhist_len;
};

// helper to insert a ballot into acc_sortbal
static void oracle_update_sortbal (oracle* O, unsigned a) {
	uint32_t *old = NULL, *new = NULL;
	for (unsigned i = 0; i < O->acc_count; ++i) {
		// insert at the first location with a ballot less than the accepted, or at the end
		if (!new && (O->acc_accbal[O->acc_sortbal[i]] < O->acc_accbal[a] 
				|| i == O->acc_count-1)) {
			
			new = &(O->acc_sortbal[i]);
		}
		if (O->acc_sortbal[i] == a) {
			old = &(O->acc_sortbal[i]);
		}
		if (old && new) break;
	}

	assert(old && new);
	if (old < new) { // shift entries up
		memmove(old, old + 1, (size_t) (new - old)*sizeof(uint32_t));
	} else if (old > new) { // shift entries down
		memmove(new + 1, new, (size_t) (old - new)*sizeof(uint32_t));
	}
	*new = O->acc_accbal[a];
}

// paxos_value comparator
#define VAL_EQUAL(a, b) (a.paxos_value_len == b.paxos_value_len && \
		a.paxos_value_val == b.paxos_value_val)

// assertions with dynamic output
#define APRINTF(cond, fmt, ...) \
	do { \
		if (!(cond)) { \
			fprintf(stderr, fmt __VA_OPT__(,) __VA_ARGS__); \
			abort(); \
		} \
	} \
	while (0) // force semicolon

/*-----Message handlers-----*/
static void oracle_assert_invariants (oracle* O) {
	// check Validity
	for (unsigned a = 0; a < O->acc_count; ++a) {
		paxos_value av = O->acc_accval[a];
		if (av.paxos_value_len == 0) continue; // no value accepted by this acceptor
		// find client that proposed value
		bool cli_prop = false;
		for (unsigned i = O->cli_vhist_len-1; i < O->cli_vhist_len; --i) {
			if (VAL_EQUAL(O->cli_vhist[i], av)) {
				cli_prop = true;
				break;
			}
		}
		APRINTF(cli_prop, "INV Validity violated: Acceptor %u accepts value %s (ballot %u) \
				never proposed by a client.\n", a, av.paxos_value_val, O->acc_accbal[a]);
		// find proposer that proposed value
		bool pro_prop = false;
		for (unsigned i = O->pro_vhist_len-1; i < O->pro_vhist_len; --i) {
			if (VAL_EQUAL(O->pro_vhist[i], av)) {
				pro_prop = true;
				break;
			}
		}
		APRINTF(pro_prop, "INV Validity violated: Acceptor %u accepts value %s (ballot %u) \
				proposed by a client but not a proposer.\n", 
				a, av.paxos_value_val, O->acc_accbal[a]);
	}

	// check Agreement1
	for (unsigned a = 0; a < O->acc_count; ++a) {
		APRINTF(O->acc_accbal[a] < O->acc_prombal[a] || O->acc_accbal[a] == UINT_MAX, 
				"INV Agreement1 violated: Acceptor %u accepts value %s with ballot %u, \
				but has promised to consider only ballots >= %u.\n", 
				a, O->acc_accval[a].paxos_value_val, O->acc_accbal[a], O->acc_prombal[a]);
		
	}

	// check Agreement2
	const unsigned quorum = O->acc_count/2 + 1;
	for (unsigned p = 0; p < O->pro_count; ++p) {
		paxos_value pv = O->pro_propval[p];
		unsigned empty = 0; // acceptors with no accepted value
		unsigned notinq = 0; // acceptors with a ballot > the prev ballot for the prop value
		unsigned prev_bal = UINT_MAX;
		for (unsigned i = 0; i < O->acc_count; ++i) {
			if (O->acc_accbal[O->acc_sortbal[i]] == UINT_MAX) { // no accepted value
				++empty;
				if (empty == quorum) break;
			} else if (VAL_EQUAL(O->acc_accval[O->acc_sortbal[i]], pv)) {
				prev_bal = O->acc_accbal[O->acc_sortbal[i]];
				break;
			} else { // accepted a value with a ballot > the prev ballot
				++notinq;
			}
		}
		APRINTF(empty >= quorum || notinq < quorum,
				"INV Agreement2 violated: Proposer %u has proposed value %s with previous \
				accepted ballot %d, but there are %u acceptors that have previously \
				accepted a value with a greater ballot (empty = %u, quorum = %u) \
				than the highest for that value.",
				p, pv.paxos_value_val, (prev_bal == UINT_MAX) ? -1 : (int) prev_bal,
				notinq, empty, quorum);
	}
}

static void oracle_handle_prepare(paxos_message* msg, oracle* O) {
	paxos_prepare* prep = &msg->u.prepare; 
	O->pro_prepbal[prep->iid] = prep->ballot;
	paxos_log_info("ORACLE: saw PREPARE from prop %u with ballot %u\n", 
			prep->iid, prep->ballot);
	oracle_assert_invariants(O);
}

static void oracle_handle_promise(paxos_message* msg, oracle* O) {
	paxos_promise* prom = &msg->u.promise;
	O->acc_prombal[prom->aid] = prom->ballot;
	O->acc_lastbal[prom->aid] = prom->value_ballot;
	O->acc_lastval[prom->aid] = prom->value;
	paxos_log_info("ORACLE: saw PROMISE from acc %u with ballot %u and prev (%u, %s)",
			prom->aid, prom->ballot, prom->value_ballot, prom->value.paxos_value_val);
	oracle_assert_invariants(O);
}

static void oracle_handle_accept(paxos_message* msg, oracle* O) {
	paxos_accept* acc = &msg->u.accept;
	O->pro_propbal[acc->iid] = acc->ballot;
	O->pro_propval[acc->iid] = acc->value;
	O->pro_vhist[O->pro_vhist_len++] = acc->value;
	O->pro_vhist_len %= O->vhist_cap;
	paxos_log_info("ORACLE: saw ACCEPT from prop %u with ballot %u and value %s",
			acc->iid, acc->ballot, acc->value.paxos_value_val);
	oracle_assert_invariants(O);
}

static void oracle_handle_accepted(paxos_message* msg, oracle* O) {
	paxos_accepted* accd = &msg->u.accepted;
	O->acc_accbal[accd->aid] = accd->ballot;
	O->acc_accval[accd->aid] = accd->value;
	oracle_update_sortbal(O, accd->aid);
	paxos_log_info("ORACLE: saw ACCEPTED from acc %u with ballot %u and value %s",
			accd->aid, accd->ballot, accd->value.paxos_value_val);
	oracle_assert_invariants(O);
}

static void oracle_handle_client_value (paxos_message* msg, oracle* O) {
	paxos_client_value* cv = &msg->u.client_value;
	O->cli_vhist[O->cli_vhist_len++] = cv->value;
	O->cli_vhist_len %= O->vhist_cap;
	paxos_log_info("ORACLE: saw CLIENT_VALUE with value %s", cv->value.paxos_value_val);
	oracle_assert_invariants(O);
}

static void oracle_handle_message (oracle* O, oracle_message* M) {
	switch (M->paxmsg.type) {
	case (PAXOS_PREPARE):
		oracle_handle_prepare(&M->paxmsg, O);
		return;
	case (PAXOS_PROMISE):
		oracle_handle_promise(&M->paxmsg, O);
		return;
	case (PAXOS_ACCEPT):
		oracle_handle_accept(&M->paxmsg, O);
		return;
	case (PAXOS_ACCEPTED):
		oracle_handle_accepted(&M->paxmsg, O);
		return;
	case (PAXOS_CLIENT_VALUE):
		oracle_handle_client_value(&M->paxmsg, O);
		return;
	default:
		return;
	}
}

/*-----Oracle initialization functions-----*/
static oracle* alloc_oracle (struct evpaxos_config* tconf, unsigned vhist_cap) {
	oracle* O = calloc(1, sizeof(oracle));

	/*O->socket = -1;
	O->poll_set = malloc(max_node*sizeof(struct pollfd));
	O->poll_count = 0;
	O->msg_queue = malloc(ORACLE_MSGQ_CAP*sizeof(oracle_message));*/
	O->isock = -1;
	O->osock = -1;
	O->nohup = NULL;

	O->acc_count = tconf->acceptors_count;
	O->pro_count = tconf->proposers_count;
	
	O->acc_prombal = malloc(O->acc_count*sizeof(uint32_t));
	O->acc_accbal = malloc(O->acc_count*sizeof(uint32_t));
	O->acc_lastbal = malloc(O->acc_count*sizeof(uint32_t));
	O->acc_accval = calloc(O->acc_count, sizeof(paxos_value));
	O->acc_lastval = calloc(O->acc_count, sizeof(paxos_value));
	O->acc_sortbal = malloc(O->acc_count*sizeof(uint32_t));
	memset(O->acc_prombal, 0xff, O->acc_count*sizeof(uint32_t));
	memset(O->acc_accbal, 0xff, O->acc_count*sizeof(uint32_t));
	memset(O->acc_lastbal, 0xff, O->acc_count*sizeof(uint32_t));
	for (unsigned i = 0; i < O->acc_count; ++i) {
		// since ballots are all the same initially, just sort in ID order
		O->acc_sortbal[i] = i; 
	}

	O->pro_prepbal = malloc(O->pro_count*sizeof(uint32_t));
	O->pro_propbal = malloc(O->pro_count*sizeof(uint32_t));
	O->pro_propval = calloc(O->pro_count, sizeof(uint32_t));
	memset(O->pro_prepbal, 0xff, O->pro_count*sizeof(uint32_t));
	memset(O->pro_propbal, 0xff, O->pro_count*sizeof(uint32_t));

	O->vhist_cap = vhist_cap;
	O->pro_vhist_len = 0;
	O->cli_vhist_len = 0;
	O->pro_vhist = malloc(O->vhist_cap*sizeof(paxos_value));
	O->cli_vhist = malloc(O->vhist_cap*sizeof(paxos_value));
	return O;
}

oracle* init_oracle (struct evpaxos_config* tconf, unsigned vhist_cap, atomic_bool* nohup) {
	
	oracle* O = alloc_oracle(tconf, vhist_cap);
	O->nohup = nohup;
	
	// open the socket on which we recieve gremlin-diverted messages
	int sv[2];
	int s = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv);
	if (s == -1) {
		perror("oracle: socketpair");
		abort();
	}
	O->isock = sv[0];
	O->osock = sv[1];
	
	// initial state should pass invariants
	oracle_assert_invariants(O);
	return O;
}

void free_oracle (oracle* O) {

	free(O->acc_prombal);
	free(O->acc_lastbal);
	free(O->acc_lastval);
	free(O->acc_accbal);
	free(O->acc_accval);
	free(O->acc_sortbal);

	free(O->pro_prepbal);
	free(O->pro_propbal);
	free(O->pro_propval);
	
	free(O->pro_vhist);
	free(O->cli_vhist);

	free(O);
}

/*-----Oracle event loop-----*/
// terminated when the delay gremlin runs out of bytes and clears nohup
void* oracle_thread (void* O_v) {
	oracle* O = (oracle*) O_v;

	while (atomic_load(O->nohup)) {
		oracle_message M;
		int s = read(O->osock, &M, sizeof(oracle_message));
		assert(s == sizeof(oracle_message));
		oracle_handle_message(O, &M);
	}

	return NULL;
}

void oracle_dispatch(oracle* O) {
	pthread_t thr;
	int s = pthread_create(&thr, NULL, oracle_thread, O);
	assert(s == 0);
}

int oracle_getsock(oracle* O) {
	return O->isock;
}
