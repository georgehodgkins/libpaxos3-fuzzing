/*
 * Fuzzing testbed for libpaxos3.
 *
 * Designed for use with american fuzzy lop (afl)
 * or any other fuzzer that works by mutating an input file.
 *
 * The following knobs are controlled by the fuzzed input file:
 * - libpaxos config paramters: Passed through to node processes
 * - Network delays: by intercepting and arbitrarily delaying libevent callbacks
 * - Node failures: nodes can be stopped/started/paused at will using Linux process control
 * - Client messages: Also using process control mechanisms
 * See below for a detailed description of input format.
 *
 * The following invariants are checked by snooping on messages via libevent:
 * - Validity: No value is chosen unless it is first proposed.
 * - Agreement1: An acceptor accepts proposal n iff it has not promised to 
 *   	only consider proposals numbered m > n
 * - Agreement2: If proposal (v,n) is issued (Accept msg), there is a quorum such that 
 *   	either v belongs to the highest-numbered accepted proposal among its members, 
 *   	or no member has accepted any proposal.
 *
 *  Agreement1 and Agreement2 imply Agreement: Only one value can be accepted by a quorum.
 *    
 */

#include "paxos.h"
#include "evpaxos.h"
#include "peers.h"
#include <event2/event.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <signal.h>

#include "oracle.h"

/*----------Invariant-checking oracle-----------*/

struct oracle_s {
	struct event_base* base;
	struct peers* peers;
	unsigned acc_count;
	unsigned pro_count;
	// acceptor state
	uint32_t* acc_prombal;
	uint32_t* acc_accbal;
	paxos_value* acc_accval;
	uint32_t* acc_lastbal;
	paxos_value* acc_lastval;
	uint32_t* acc_sortbal; // acceptors sorted by last accepted ballot (for chking Agreement2)
	// proposer state
	uint32_t* pro_prepbal;
	uint32_t* pro_propbal;
	paxos_value* pro_propval;
	// proposed value histories (for checking Validity)
	unsigned vhist_cap;
	paxos_value* cli_vhist;
	unsigned cli_vhist_len;
	paxos_value* pro_vhist;
	unsigned pro_vhist_len;
};

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

// libevent callbacks
static void oracle_handle_prepare(struct peer* p, paxos_message* msg, void* arg) {
	oracle* O = (oracle*) arg;
	paxos_prepare* prep = &msg->u.prepare; 
	O->pro_prepbal[prep->iid] = prep->ballot;
	paxos_log_info("ORACLE: saw PREPARE from prop %u with ballot %u\n", 
			prep->iid, prep->ballot);
	oracle_assert_invariants(O);
}

static void oracle_handle_promise(struct peer* p, paxos_message* msg, void* arg) {
	oracle* O = (oracle*) arg;
	paxos_promise* prom = &msg->u.promise;
	O->acc_prombal[prom->aid] = prom->ballot;
	O->acc_lastbal[prom->aid] = prom->value_ballot;
	O->acc_lastval[prom->aid] = prom->value;
	paxos_log_info("ORACLE: saw PROMISE from acc %u with ballot %u and prev (%u, %s)",
			prom->aid, prom->ballot, prom->value_ballot, prom->value.paxos_value_val);
	oracle_assert_invariants(O);
}

static void oracle_handle_accept(struct peer* p, paxos_message* msg, void* arg) {
	oracle* O = (oracle*) arg;
	paxos_accept* acc = &msg->u.accept;
	O->pro_propbal[acc->iid] = acc->ballot;
	O->pro_propval[acc->iid] = acc->value;
	O->pro_vhist[O->pro_vhist_len++] = acc->value;
	O->pro_vhist_len %= O->vhist_cap;
	paxos_log_info("ORACLE: saw ACCEPT from prop %u with ballot %u and value %s",
			acc->iid, acc->ballot, acc->value.paxos_value_val);
	oracle_assert_invariants(O);
}

static void oracle_handle_accepted(struct peer* p, paxos_message* msg, void* arg) {
	oracle* O = (oracle*) arg;
	paxos_accepted* accd = &msg->u.accepted;
	O->acc_accbal[accd->aid] = accd->ballot;
	O->acc_accval[accd->aid] = accd->value;
	oracle_update_sortbal(O, accd->aid);
	paxos_log_info("ORACLE: saw ACCEPTED from acc %u with ballot %u and value %s",
			accd->aid, accd->ballot, accd->value.paxos_value_val);
	oracle_assert_invariants(O);
}

static void oracle_handle_client_value (struct peer* p, paxos_message* msg, void* arg) {
	oracle* O = (oracle*) arg;
	paxos_client_value* cv = &msg->u.client_value;
	O->cli_vhist[O->cli_vhist_len++] = cv->value;
	O->cli_vhist_len %= O->vhist_cap;
	paxos_log_info("ORACLE: saw CLIENT_VALUE with value %s", cv->value.paxos_value_val);
	oracle_assert_invariants(O);
}

static void oracle_handle_sigint (int sig, short ev, void* arg) {
	struct event_base* base = arg;
	event_base_loopexit(base, NULL);
}

// TODO: handle repeat, trim, preempted, acceptor_state

static void oracle_connect_to_proposers(oracle* O, struct evpaxos_config* tconf) {
	for (int i = 0; i < O->pro_count; ++i) {
		struct sockaddr_in addr = evpaxos_proposer_address(tconf, i);
		peers_connect(O->peers, i, &addr);
	}
}

static oracle* alloc_oracle (struct evpaxos_config* tconf, unsigned vhist_cap) {
	oracle* O = calloc(1, sizeof(oracle));

	O->base = event_base_new();
	O->peers = NULL;

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

oracle* init_oracle (struct evpaxos_config* tconf, unsigned vhist_cap, int port) {
	
	oracle* O = alloc_oracle(tconf, vhist_cap);
	O->base = event_base_new();
	struct event* sigint_ev = evsignal_new(O->base, SIGINT, oracle_handle_sigint, O);
	evsignal_add(sigint_ev, NULL);

	O->peers = peers_new(O->base, tconf);
		
	// connect to acceptors and proposers
	peers_connect_to_acceptors(O->peers);
	oracle_connect_to_proposers(O, tconf);

	if (peers_listen(O->peers, port) == 0) {
		free(O);
		return NULL;
	}

	peers_subscribe(O->peers, PAXOS_PREPARE, oracle_handle_prepare, O);
	peers_subscribe(O->peers, PAXOS_PROMISE, oracle_handle_promise, O);
	peers_subscribe(O->peers, PAXOS_ACCEPT, oracle_handle_accept, O);
	peers_subscribe(O->peers, PAXOS_ACCEPTED, oracle_handle_accepted, O);
	peers_subscribe(O->peers, PAXOS_CLIENT_VALUE, oracle_handle_client_value, O);

	// initial state should pass invariants
	oracle_assert_invariants(O);
	return O;
}

void free_oracle (oracle* O) {
	event_base_free(O->base);
	peers_free(O->peers);

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

void* oracle_dispatch_thrd (void* O_v) {
	oracle* O = (oracle*) O_v;
	event_base_dispatch(O->base);
	return NULL;
}
