#include <stdio.h>
#include <fcntl.h>
#define _GNU_SOURCE
#include <getopt.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>
#include "gremlin.h"

#define DEFAULT_LENGTH 256
#define DEFAULT_FILE "vector.fuzz"

int main (int argc, char** argv) {
	
	size_t len = DEFAULT_LENGTH;
	uint32_t rf_seed = 0;
	uint32_t gen_seed = 0;
	char* file = NULL;
	bool use_rf = false;
	delay_policy_t dpol = (delay_policy_t) 0xff;

	enum OPT_ID {OPT_SEED = 's', OPT_RAND = 'R', OPT_LEN = 'L', OPT_FILE = 'o',
	OPT_SINGLE, OPT_PERMSG, OPT_PERNODE_R, OPT_PERNODE_S = 8,
	OPT_PERNET, OPT_FIXED, OPT_NONE};

	const struct option longopts[] = {
		{"seed", required_argument, NULL, OPT_SEED},
		{"random-factor", no_argument, NULL, OPT_RAND},
		{"length", required_argument, NULL, OPT_LEN},
		{"filename", required_argument, NULL, OPT_FILE},
		{"single-factor", no_argument, NULL, OPT_SINGLE},
		{"permsg-factor", no_argument, NULL, OPT_PERMSG},
		{"pernode-recv-factor", no_argument, NULL, OPT_PERNODE_R},
		{"pernode-send-factor", no_argument, NULL, OPT_PERNODE_S},
		{"pernet-factor", no_argument, NULL, OPT_PERNET},
		{"fixed-factor", no_argument, NULL, OPT_FIXED},
		{"no-factor", no_argument, NULL, OPT_NONE},
		{0, 0, 0, 0}};

	int o;
	while ( (o = getopt_long(argc, argv, "s:RL:o:", longopts, NULL)) != -1) {
		switch (o) {
		case OPT_SEED:
			gen_seed = atoi(optarg);
			if (gen_seed == 0) {
				printf("%s is not a valid 32-bit unsigned seed.\n", optarg);
				exit(1);
			}
			break;
		case OPT_RAND:
			use_rf = true;
			break;
		case OPT_LEN:
			len = (size_t) atoi(optarg);
			if (len == 0) {
				printf("%s is not a valid byte count.\n", optarg);
				exit(1);
			}
			break;
		case OPT_FILE:
			file = strdup(optarg);
			if (!file) {
				perror("strdup");
				exit(1);
			}
			break;
		case OPT_SINGLE:
			dpol = BSAF_UNIFIED;
			break;
		case OPT_PERMSG:
			dpol = BSAF_PERMSG;
			break;
		case OPT_PERNODE_R:
			dpol = BSAF_PERNODE_RECIEVER;
			break;
		case OPT_PERNODE_S:
			dpol = BSAF_PERNODE_SENDER;
			break;
		case OPT_PERNET:
			dpol = BSAF_PERNET;
			break;
		case OPT_FIXED:
			dpol = FIXED_PERNODE;
			break;
		case OPT_NONE:
			dpol = NONE;
			break;
		default:
			printf("Unknown option %c [%c]\n", o, optopt);
		}
	}

	if (gen_seed) {
		srandom(gen_seed);
	} else {
		srandom(time(NULL));
	}

	char polbyte;
	if (dpol == (delay_policy_t) 0xff) { // pick policy at random
		polbyte = (char) random();
		polbyte &= ~0xf; // TODO: node control policy
	} else {
		polbyte = ((unsigned char) dpol) << 4;
	}

	if (use_rf) polbyte |= 0x80;
	else polbyte &= ~0x80;
	
	if (!file) file = strdup(DEFAULT_FILE);
	
	int fd = open(file, O_CREAT | O_RDWR | O_TRUNC, 0666);
	if (fd == -1) {
		perror("open");
		exit(1);
	}

	off_t tlen = 1 + policy_reqd_size[dpol] + len;
	int s = ftruncate(fd, tlen);
	if (s == -1) {
		perror("ftruncate");
		exit(1);
	}

	s = write(fd, &polbyte, 1);
	assert(s == 1);

	// generate test bytes
	char* vec = malloc(tlen - 1);
	for (unsigned i = 0; i < tlen-1; ++i) {
		vec[i] = (char) random();
	}

	// write out file
	s = write(fd, vec, tlen-1);
	assert(s == tlen-1);
	close(fd);

	free(vec);
	free(file);
	return 0;
}
	
