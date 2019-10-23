/*********************************************************************
 *                     openNetVM
 *              https://sdnfv.github.io
 *
 *   BSD LICENSE
 *
 *   Copyright(c)
 *            2015-2019 George Washington University
 *            2015-2019 University of California Riverside
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * The name of the author may not be used to endorse or promote
 *       products derived from this software without specific prior
 *       written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * speed_tester.c - create pkts and loop through NFs.
 ********************************************************************/

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ring.h>

#ifdef LIBPCAP
#include <pcap.h>
#endif

#include "onvm_flow_table.h"
#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"

#define NF_TAG "fork_tester"

#define PKTMBUF_POOL_NAME "MProc_pktmbuf_pool"
#define PKT_READ_SIZE ((uint16_t)32)
#define SPEED_TESTER_BIT 7
#define LATENCY_BIT 6
#define LOCAL_EXPERIMENTAL_ETHER 0x88B5
#define DEFAULT_PKT_NUM 128
#define DEFAULT_LAT_PKT_NUM 16
#define MAX_PKT_NUM NF_QUEUE_RINGSIZE

#define MAX_PRIMES_NUM 50000

/*user defined packet size and destination mac address
*size defaults to ethernet header length
*/
static uint16_t packet_size = ETHER_HDR_LEN;
static uint8_t d_addr_bytes[ETHER_ADDR_LEN];

/*  track the -c option to see if it has been filled */
static uint8_t use_custom_pkt_count = 0;
/* Default number of packets: 128; user can modify it by -c <packet_number> in command line */
static uint32_t packet_number = 0;

/* Variables for measuring packet latency */
static uint8_t measure_latency = 0;

/*
 * Variables needed to replay a pcap file
 */
char *pcap_filename = NULL;

static int fork_flag = 0;

void
nf_setup(struct onvm_nf_local_ctx *nf_local_ctx);

/*
 * Print a usage message
 */
static void
usage(const char *progname) {
        printf("Usage:\n");
        printf(
            "%s [EAL args] -- [NF_LIB args] -- -d <destination> [-p <print_delay>] "
            "[-s <packet_length>] [-m <dest_mac_address>] [-o <pcap_filename>] "
            "[-c <packet_number>] [-l]\n",
            progname);
        printf("%s -F <CONFIG_FILE.json> [EAL args] -- [NF_LIB args] -- [NF args]\n\n", progname);
        printf("Flags:\n");
        printf(" - `-d DST`: Destination Service ID to foward to\n");
        printf(" - `-p PRINT_DELAY`: Number of packets between each print, e.g. `-p 1` prints every packets.\n");
        printf(
            " - `-s PACKET_SIZE`: Size of packet, e.g. `-s 32` allocates 32 bytes for the data segment of "
            "`rte_mbuf`.\n");
        printf(
            " - `-m DEST_MAC`: User specified destination MAC address, e.g. `-m aa:bb:cc:dd:ee:ff` sets the "
            "destination address within the ethernet header that is located at the start of the packet data.\n");
        printf(" - `-o PCAP_FILENAME` : The filename of the pcap file to replay\n");
        printf(
            " - `-l LATENCY` : Enable latency measurement. This should only be enabled on one Speed Tester NF. Packets "
            "must be routed back to the same speed tester NF.\n");
        printf(
            " - `-c PACKET_NUMBER` : Use user specified number of packets in the batch. If not specified then this "
            "defaults to 128.\n");
}

/*
 * Parse the application arguments.
 */
static int
parse_app_args(int argc, char *argv[], const char *progname) {
        int c, i, count = 0;
        int values[ETHER_ADDR_LEN];

        while ((c = getopt(argc, argv, "fs:m:o:c:l")) != -1) {
                switch (c) {
                        case 'f':
                                fork_flag = 1;
                                break;
                        case 's':
                                packet_size = strtoul(optarg, NULL, 10);
                                break;
                        case 'm':
                                count = sscanf(optarg, "%x:%x:%x:%x:%x:%x", &values[0], &values[1], &values[2],
                                               &values[3], &values[4], &values[5]);
                                if (count == ETHER_ADDR_LEN) {
                                        for (i = 0; i < ETHER_ADDR_LEN; ++i) {
                                                d_addr_bytes[i] = (uint8_t)values[i];
                                        }
                                } else {
                                        usage(progname);
                                        return -1;
                                }
                                break;
                        case 'o':
#ifdef LIBPCAP
                                pcap_filename = strdup(optarg);
                                break;
#else
                                rte_exit(EXIT_FAILURE,
                                         "To enable pcap replay follow the README "
                                         "instructins\n");
                                break;
#endif
                        case 'c':
                                use_custom_pkt_count = 1;
                                packet_number = strtoul(optarg, NULL, 10);
                                if (packet_number > MAX_PKT_NUM) {
                                        RTE_LOG(INFO, APP, "Illegal packet number(1 ~ %u) %u!\n", MAX_PKT_NUM,
                                                packet_number);
                                        return -1;
                                }
                                break;
                        case 'l':
                                measure_latency = 1;
                                break;
                        case '?':
                                usage(progname);
                                if (optopt == 'd')
                                        RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                                else if (optopt == 'p')
                                        RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                                else if (optopt == 's')
                                        RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                                else if (optopt == 'm')
                                        RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                                else if (optopt == 'c')
                                        RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                                else if (isprint(optopt))
                                        RTE_LOG(INFO, APP, "Unknown option `-%c'.\n", optopt);
                                else
                                        RTE_LOG(INFO, APP, "Unknown option character `\\x%x'.\n", optopt);
                                return -1;
                        default:
                                usage(progname);
                                return -1;
                }
        }

        return optind;
}

__attribute__((unused))
static void
do_fork(void) {
        static int has_split = 0;
        if (!has_split) {
            printf("Forking\n");
            has_split = 1;
            onvm_nflib_fork();
        }
}

static int
packet_handler(__attribute__((unused)) struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
               __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
        static int has_forked = 0;

        if (!ONVM_CHECK_BIT(meta->flags, SPEED_TESTER_BIT)) {
                meta->action = ONVM_NF_ACTION_DROP;
                return 0;
        }

        if (fork_flag && nf_local_ctx->nf->resource_usage.cpu_time_proportion > 0.05 && !has_forked) {
                has_forked = 1;
                printf("Forking...\n");
                onvm_nflib_fork();
        }
        
        if (has_forked) {
                static int my_turn = 0;
                my_turn = !my_turn;
                if (!my_turn) { 
                        meta->action = ONVM_NF_ACTION_TONF;
                        meta->destination = 2; 
                        return 0;
                }
        }

        int i, num = 0, primes = 0;
        static int max_num = 5000;
        if (!fork_flag) {
                printf("(Child) ");
        }
        printf("Parsing a %d MB file...", max_num);
        while (num <= max_num) { 
                i = 2; 
                while (i <= num) { 
                        if(num % i == 0)
                                break;
                        i++; 
                }
                if (i == num)
                        primes++;

                num++;
        }
        max_num = (max_num > MAX_PRIMES_NUM) ? max_num : max_num + 5000;
        printf(" Done!\n");

        // Hack to stop compiler from optimizing.
        meta->src = primes;

        meta->action = ONVM_NF_ACTION_TONF;
        meta->destination = 3;

        return 0;
}

int
main(int argc, char *argv[]) {
        struct onvm_nf_local_ctx *nf_local_ctx;
        struct onvm_nf_function_table *nf_function_table;
        int arg_offset;

        const char *progname = argv[0];

        nf_local_ctx = onvm_nflib_init_nf_local_ctx();

        onvm_nflib_start_signal_handler(nf_local_ctx, NULL);

        nf_function_table = onvm_nflib_init_nf_function_table();
        nf_function_table->pkt_handler = &packet_handler;
//        nf_function_table->setup = &nf_setup;

        if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG, nf_local_ctx, nf_function_table)) < 0) {
                printf("Service ID: %d\n", nf_local_ctx->nf->service_id);
                onvm_nflib_stop(nf_local_ctx);
                if (arg_offset == ONVM_SIGNAL_TERMINATION) {
                        printf("Exiting due to user termination\n");
                        return 0;
                } else {
                        rte_exit(EXIT_FAILURE, "Failed ONVM init\n");
                }
        }

        argc -= arg_offset;
        argv += arg_offset;

        if (parse_app_args(argc, argv, progname) < 0) {
                onvm_nflib_stop(nf_local_ctx);
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
        }

        onvm_nflib_run(nf_local_ctx);

        onvm_nflib_stop(nf_local_ctx);
        printf("If we reach here, program is ending\n");
        return 0;
}
