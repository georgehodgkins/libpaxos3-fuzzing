# libpaxos3-fuzzing

 Fuzzing testbed for libpaxos3, intended to discover violations of the Paxos spec (no offense
 intended to the libpaxos3 developers). WIP. All of the testbed code is in the `fuzz`
 directory; everything else is libpaxos3.

 Designed for use with american fuzzy lop (afl)
 or any other fuzzer that works by mutating an input vector. Uses Linux OS APIs extensively
 for reliable communication channels and node management.

 Consists of two components: the gremlin, which injects fuzz into the system
 based on the input vector, and the oracle, which checks the invariants.

## Gremlin
	
	The gremlin itself has two functional components: the delay gremlin and the 
	node gremlin. The delay gremlin interposes at the point of message send using
	a preloader mechanism, and injects delay according to the chosen delay policy.
	The delay gremlin is also responsible for sending copies of messages to the oracle
	(after any injected delay).

	The following delay policies (formulae for calculating delay) are available:
	- Fixed: a single factor is multiplied by a byte from the input vector.
	- Per-message: a factor determined by the message type is multiplied by
		a byte from the input vector.
	- Per-node: a factor determined by the sending or recieving node (separate policies) is 
		multiplied by a byte from the input vector.
	- Size-based: a single factor is multiplied by the size of the message.
	- Per-network: one factor is used for messages between proposers and acceptors,
		and one for messages between proposers and clients.
	- None: no delay.

	Any of these options can be paired with a random delay factor. All factors are 16-bit
	values initialized from the beginning of the input vector (see the parsers in 
	delay-gremlin.c).

	The node gremlin is responsible for starting, pausing, and terminating nodes
	(Linux processes) according to the input vector. No fuzzing functionality is currently
	implemented for the node gremlin (only basic APIs to start and terminate nodes).

## Oracle
	
	The oracle is responsible for checking invariants based on the messages diverted to it
	by the delay gremlin. It checks the following invariants 
	([source](https://www.cs.yale.edu/homes/aspnes/pinewiki/Paxos.html)):

	 - Validity: No value is accepted unless it is first proposed.
	 - Agreement1: An acceptor accepts proposal n iff it has not promised to 
		only consider proposals numbered m > n
	 - Agreement2: If proposal (v,n) is issued (Accept msg), there is a quorum such that 
		either v belongs to the highest-numbered accepted proposal among its members, 
		or no member has accepted any proposal.

	  Agreement1 AND Agreement2 == Agreement: Only one value can be accepted by a quorum.
    
	The full set of invariants is checked after each message is processed. The oracle makes
	use of libpaxos APIs to interpret messages.

## Input format

	The testbed is designed to take an arbitrary binary file as input (although many
	existing binary formats would be suboptimal, due to the heavy dependence on the initial
	byte, which is constant for many formats). The first byte specifies the fuzzing policy.
	Currently, the MSB specifies whether 
	a random factor should be used for delay injection, the next three bits specify the
	delay injection policy to use (see above), and the four low bits are currently unused,
	reserved for specifying node fuzzing policy when that is implemented.

	After the first byte, a policy-dependent number of bytes is used to initialize fuzzing
	state. If a random factor is selected, the first four bytes after the initial byte are
	interpreted as a seed for random number generation, followed by any bytes needed for
	policy parameters (for instance, the per-node policies take three 16-bit values from
	the vector to use as fixed factors for the three types of node).

	The remainder of the bytes are used as an input vector as described in the delay
	fuzzing section (and would be used for node fuzzing as well). In addition, the length
	of the vector directly specifies the length of the test run: the number of bytes in the
	input vector (minus bytes used at startup) is the number of messages that will be passed
	before the testbed exits (assuming no errors occur).

