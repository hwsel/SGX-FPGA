/*

Copyright 2018 Intel Corporation

This software and the related documents are Intel copyrighted materials,
and your use of them is governed by the express license under which they
were provided to you (License). Unless the License provides otherwise,
you may not use, modify, copy, publish, distribute, disclose or transmit
this software or the related documents without Intel's prior written
permission.

This software and the related documents are provided as is, with no
express or implied warranties, other than those that are expressly stated
in the License.

*/


using namespace std;

#include "config.h"
# include "Enclave_u.h"
#if !defined(SGX_HW_SIM)&&!defined(_WIN32)
#include "sgx_stub.h"
#endif
#include <iostream>
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <time.h>
#include <sgx_urts.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <openssl/evp.h>
#include <getopt.h>
#include <unistd.h>
#include <sgx_uae_service.h>
#include <sgx_ukey_exchange.h>
#include <string>
#include "common.h"
#include "protocol.h"
#include "sgx_detect.h"
#include "sgx_dh.h"
#include "hexutil.h"
#include "fileio.h"
#include "base64.h"
#include "crypto.h"
#include "msgio.h"
#include "logfile.h"
#include "quote_size.h"

#define UNIXSTR_PATH "/tmp/unix.str"
#define UNIXDP_PATH "/tmp/unix.make"

#ifdef _WIN32
# define strdup(x) _strdup(x)
#else
# define _rdrand64_step(x) ({ unsigned char err; asm volatile("rdrand %0; setc %1":"=r"(*x), "=qm"(err)); err; })
#endif

#ifdef __x86_64__
#define DEF_LIB_SEARCHPATH "/lib:/lib64:/usr/lib:/usr/lib64"
#else
#define DEF_LIB_SEARCHPATH "/lib:/usr/lib"
#endif

typedef struct config_struct {
	char mode;
	uint32_t flags;
	sgx_spid_t spid;
	sgx_ec256_public_t pubkey;
	sgx_quote_nonce_t nonce;
	char *server;
	char *port;
} config_t;

typedef struct ra_proof {
	int eid;
	uint32_t gid;
} ra_proof_t;

typedef struct net_connector {
	char * server;
	char *port;
} net_connector_t;

const char publicKey[452] ="-----BEGIN PUBLIC KEY-----\n"\
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n"\
"ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+\n"\
"vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp\n"\
"fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68\n"\
"i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV\n"\
"PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy\n"\
"wQIDAQAB\n"\
"-----END PUBLIC KEY-----\n";

char certificate[351]="W8+cDyhKnmqqA0RU/mu9xEouJFDwhrr69JI6KYthwbQ9aMppf/YQQbjGipMqR0PU\n"\
"MuhFYBXAhdZL0V2dxQi0ja7vrE8DUqosITLc2ftuqUfr/aQqxSHWLWn0sKGEnkXZ\n"\
"txZY8SnaTYuykeG2b29HycKXc9SO4RIgXJ9YdhHGYZX4JkvQQq+p5SbZkbc6+A4o\n"\
"fokJBJZoeDDXlFhM168T7LICslvVFZPA7XkCcw+pZf+erk5eb2s+/HTyM0oT+iEJ\n"\
"3Fow54bcZ9mjSTQfzeJk1WogmN+STmMiKnYZDil80dH7GJVWy5kN9RotFDhtTxOf\n"\
"PV/uhv/MkTC5krZ9QfX5bQ==\n";

int file_in_searchpath (const char *file, const char *search, char *fullpath,
	size_t len);

sgx_status_t sgx_create_enclave_search (
	const char *filename,
	const int edebug,
	sgx_launch_token_t *token,
	int *updated,
	sgx_enclave_id_t *eid,
	sgx_misc_attribute_t *attr
);



void usage();
int do_quote(sgx_enclave_id_t eid, config_t *config);
int do_attestation(sgx_enclave_id_t eid, config_t *config);
int attestation_fpga(sgx_enclave_id_t eid, int client_sockfd_adapter);
int ctrl_process_data(sgx_enclave_id_t eid, int client_sockfd_adapter);
int verify_application(sgx_enclave_id_t src_eid, MsgIO* msgio);
int key_exchange_client(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, MsgIO* msgio);
int ctrl_process_data_ocall(sgx_enclave_id_t eid, int client_sockfd_adapter);

char debug = 0;
char verbose = 0;
//connector to client
MsgIO *msgio;

#define MODE_ATTEST 0x0
#define MODE_EPID 	0x1
#define MODE_QUOTE	0x2

#define OPT_PSE		0x01
#define OPT_NONCE	0x02
#define OPT_LINK	0x04
#define OPT_PUBKEY	0x08

/* Macros to set, clear, and get the mode and options */

#define SET_OPT(x,y)	x|=y
#define CLEAR_OPT(x,y)	x=x&~y
#define OPT_ISSET(x,y)	x&y

# define ENCLAVE_NAME "Enclave.signed.so"

void emit_debug(const uint8_t *buf, size_t data_size)

{
    printf("DEBUG: \n");
    for(int i=0;i<data_size;i++)
    printf("0x%x ", buf[i]);
    printf("\n");
}

uint32_t session_request_ocall(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, sgx_dh_msg1_t* dh_msg1, uint32_t* session_id)
{	
	unsigned char buffer[50];
	msgio->read((void **)&buffer, NULL);
	memcpy(dh_msg1, buffer, sizeof(&dh_msg1));
	memcpy(session_id, buffer+sizeof(&dh_msg1), sizeof(session_id));
}

uint32_t exchange_report_ocall(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, sgx_dh_msg2_t *dh_msg2, sgx_dh_msg3_t *dh_msg3, uint32_t session_id)
{
	msgio->read((void **)dh_msg3, NULL);
}

int main (int argc, char *argv[])
{
	config_t config;
	sgx_launch_token_t token= { 0 };
	sgx_status_t status;
	sgx_enclave_id_t eid= 0;
	int updated= 0;
	int sgx_support;
	uint32_t i;
	EVP_PKEY *service_public_key= NULL;
	char have_spid= 0;
	char flag_stdio= 0;

	/* Create a logfile to capture debug output and actual msg data */
	//fplog = create_logfile("client.log");
	//dividerWithText(fplog, "Client Log Timestamp");

	const time_t timeT = time(NULL);
	struct tm lt, *ltp;


	ltp = localtime(&timeT);
	if ( ltp == NULL ) {
		perror("localtime");
		return 1;
	}
	lt= *ltp;

	memset(&config, 0, sizeof(config));
	config.mode= MODE_ATTEST;

	static struct option long_opt[] =
	{
		{"help",		no_argument,		0, 'h'},		
		{"debug",		no_argument,		0, 'd'},
		{"epid-gid",	no_argument,		0, 'e'},
		{"pse-manifest",
						no_argument,    	0, 'm'},
		{"nonce",		required_argument,	0, 'n'},
		{"nonce-file",	required_argument,	0, 'N'},
		{"rand-nonce",	no_argument,		0, 'r'},
		{"spid",		required_argument,	0, 's'},
		{"spid-file",	required_argument,	0, 'S'},
		{"linkable",	no_argument,		0, 'l'},
		{"pubkey",		optional_argument,	0, 'p'},
		{"pubkey-file",	required_argument,	0, 'P'},
		{"quote",		no_argument,		0, 'q'},
		{"verbose",		no_argument,		0, 'v'},
		{"stdio",		no_argument,		0, 'z'},
		{ 0, 0, 0, 0 }
	};

	/* Parse our options */

	while (1) {
		int c;
		int opt_index= 0;
		unsigned char keyin[64];

		c= getopt_long(argc, argv, "N:P:S:dehlmn:p:qrs:vz", long_opt,
			&opt_index);
		if ( c == -1 ) break;

		switch(c) {
		case 0:
			break;
		case 'N':
			if ( ! from_hexstring_file((unsigned char *) &config.nonce,
					optarg, 16)) {

				fprintf(stderr, "nonce must be 32-byte hex string\n");
				exit(1);
			}
			SET_OPT(config.flags, OPT_NONCE);

			break;
		case 'P':
			if ( ! key_load_file(&service_public_key, optarg, KEY_PUBLIC) ) {
				fprintf(stderr, "%s: ", optarg);
				crypto_perror("key_load_file");
				exit(1);
			} 

			if ( ! key_to_sgx_ec256(&config.pubkey, service_public_key) ) {
				fprintf(stderr, "%s: ", optarg);
				crypto_perror("key_to_sgx_ec256");
				exit(1);
			}
			SET_OPT(config.flags, OPT_PUBKEY);

			break;
		case 'S':
			if ( ! from_hexstring_file((unsigned char *) &config.spid,
					optarg, 16)) {

				fprintf(stderr, "SPID must be 32-byte hex string\n");
				exit(1);
			}
			++have_spid;

			break;
		case 'd':
			debug= 1;
			break;
		case 'e':
			config.mode= MODE_EPID;
			break;
		case 'l':
			SET_OPT(config.flags, OPT_LINK);
			break;
		case 'm':
			SET_OPT(config.flags, OPT_PSE);
			break;
		case 'n':
			if ( strlen(optarg) < 32 ) {
				fprintf(stderr, "nonce must be 32-byte hex string\n");
				exit(1);
			}
			if ( ! from_hexstring((unsigned char *) &config.nonce,
					(unsigned char *) optarg, 16) ) {

				fprintf(stderr, "nonce must be 32-byte hex string\n");
				exit(1);
			}

			SET_OPT(config.flags, OPT_NONCE);

			break;
		case 'p':
			if ( ! from_hexstring((unsigned char *) keyin,
					(unsigned char *) optarg, 64)) {

				fprintf(stderr, "key must be 128-byte hex string\n");
				exit(1);
			}

			/* Reverse the byte stream to make a little endien style value */
			for(i= 0; i< 32; ++i) config.pubkey.gx[i]= keyin[31-i];
			for(i= 0; i< 32; ++i) config.pubkey.gy[i]= keyin[63-i];

			SET_OPT(config.flags, OPT_PUBKEY);

			break;
		case 'q':
			config.mode = MODE_QUOTE;
			break;
		case 'r':
			for(i= 0; i< 2; ++i) {
				int retry= 10;
				unsigned char ok= 0;
				uint64_t *np= (uint64_t *) &config.nonce;

				while ( !ok && retry ) ok= _rdrand64_step(&np[i]);
				if ( ok == 0 ) {
					fprintf(stderr, "nonce: RDRAND underflow\n");
					exit(1);
				}
			}
			SET_OPT(config.flags, OPT_NONCE);
			break;
		case 's':
			if ( strlen(optarg) < 32 ) {
				fprintf(stderr, "SPID must be 32-byte hex string\n");
				exit(1);
			}
			if ( ! from_hexstring((unsigned char *) &config.spid,
					(unsigned char *) optarg, 16) ) {

				fprintf(stderr, "SPID must be 32-byte hex string\n");
				exit(1);
			}
			++have_spid;
			break;
		case 'v':
			verbose= 1;
			break;
		case 'z':
			flag_stdio= 1;
			break;
		case 'h':
		case '?':
		default:
			usage();
		}
	}

	argc-= optind;
	if ( argc > 1 ) usage();

	/* Remaining argument is host[:port] */

	if ( flag_stdio && argc ) usage();
	else if ( !flag_stdio && ! argc ) {
		// Default to localhost
		config.server= strdup("172.31.129.142");
		if ( config.server == NULL ) {
			perror("malloc");
			return 1;
		}
	} else if ( argc ) {
		char *cp;

		config.server= strdup(argv[optind]);
		if ( config.server == NULL ) {
			perror("malloc");
			return 1;
		}
		
		/* If there's a : then we have a port, too */
		cp= strchr(config.server, ':');
		if ( cp != NULL ) {
			*cp++= '\0';
			config.port= cp;
		}
	}

	if ( ! have_spid && config.mode != MODE_EPID ) {
		fprintf(stderr, "SPID required. Use one of --spid or --spid-file \n");
		return 1;
	}

	/* Can we run SGX? */

#ifndef SGX_HW_SIM
	sgx_support = get_sgx_support();
	if (sgx_support & SGX_SUPPORT_NO) {
		fprintf(stderr, "This system does not support Intel SGX.\n");
		return 1;
	} else {
		if (sgx_support & SGX_SUPPORT_ENABLE_REQUIRED) {
			fprintf(stderr, "Intel SGX is supported on this system but disabled in the BIOS\n");
			return 1;
		}
		else if (sgx_support & SGX_SUPPORT_REBOOT_REQUIRED) {
			fprintf(stderr, "Intel SGX will be enabled after the next reboot\n");
			return 1;
		}
		else if (!(sgx_support & SGX_SUPPORT_ENABLED)) {
			fprintf(stderr, "Intel SGX is supported on this sytem but not available for use\n");
			fprintf(stderr, "The system may lock BIOS support, or the Platform Software is not available\n");
			return 1;
		}
	} 
#endif

	status = sgx_create_enclave_search(ENCLAVE_NAME,
		SGX_DEBUG_FLAG, &token, &updated, &eid, 0);
	//printf("eid = %" PRId64 "\n", eid);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_create_enclave: %s: %08x\n",
			ENCLAVE_NAME, status);
		if ( status == SGX_ERROR_ENCLAVE_FILE_ACCESS ) 
			fprintf(stderr, "Did you forget to set LD_LIBRARY_PATH?\n");
		return 1;
	}

	timespec tv_1;
	clock_gettime(CLOCK_MONOTONIC,&tv_1);

	if ( config.mode == MODE_ATTEST ) {		
		//attestation start
		//do_attestation(eid, &config);
		//verify app
		
		int rv;
		uint8_t* encrypted_results;
		size_t result_length;
		int result = -1;		
		msgio = new MsgIO(NULL, DEFAULT_PORT);
		while(msgio->server_loop())
		{
			timespec tv3;
			clock_gettime(CLOCK_MONOTONIC, &tv3);
			//not verified client yet
			if(result == -1)
				result = verify_application(eid, msgio);

			timespec tv4;
			clock_gettime(CLOCK_MONOTONIC, &tv4);
			printf("The attestation time is: %ld\n", tv4.tv_sec*1000*1000 + tv4.tv_nsec/1000 - (tv3.tv_sec*1000*1000 + tv3.tv_nsec/1000));
			//fail in verification
			if(result == 0)
			{
				eprintf("verification fail.\n");
				msgio->disconnect();
				return 0;
			}
			if(result == 1) 
			{	//key exchange with client
				//key_exchange_client();
				//attest with FPGA
				timespec tv_11;
				clock_gettime(CLOCK_MONOTONIC, &tv_11);
				eprintf("establishing the path to fpga...\n");

				int server_sockfd_adapter = -1;
				int client_sockfd_adapter = -1;               
				socklen_t client_adapter_len;
				struct sockaddr_un server_addr_adapter;
				struct sockaddr_un client_addr_adapter;
				server_sockfd_adapter = socket(AF_LOCAL, SOCK_STREAM, 0);
				unlink(UNIXSTR_PATH);
				bzero(&server_addr_adapter, sizeof(server_addr_adapter));
				server_addr_adapter.sun_family = AF_LOCAL;
				strcpy(server_addr_adapter.sun_path, UNIXSTR_PATH);
				bind(server_sockfd_adapter, (struct sockaddr*)&server_addr_adapter, sizeof(server_addr_adapter));
				listen(server_sockfd_adapter, 5);
				client_sockfd_adapter = accept(server_sockfd_adapter, (struct sockaddr*)&client_addr_adapter, &client_adapter_len); 
			
				int result_fpga = attestation_fpga(eid, client_sockfd_adapter);
				if(result_fpga == 1)
				{
					eprintf("path establish success.\n");
				}
				timespec tv_12;
				clock_gettime(CLOCK_MONOTONIC, &tv_12);
				// FILE *pFile;
				// pFile = fopen("att_fpga.txt", "a");	

				printf("VERIFY FPGA: %ld us\n", (tv_12.tv_sec*1000*1000 + tv_12.tv_nsec/1000) - (tv_11.tv_sec*1000*1000 + tv_11.tv_nsec/1000));
				// fprintf(pFile, "%ld\n", (tv_12.tv_sec*1000*1000 + tv_12.tv_nsec/1000) - (tv_11.tv_sec*1000*1000 + tv_11.tv_nsec/1000));
				// fclose(pFile);
				//success - start processing data
				if(result_fpga == 1)
				{
					eprintf("path establish success.\n");
					
					ctrl_process_data_ocall(eid, client_sockfd_adapter);
				}			
				else //fail, tell client
				{				
					eprintf("path establish fail.\n");
				}
				close(client_sockfd_adapter);
				close(server_sockfd_adapter);	

				//reset connection
				result = -1;
			}

		}
		msgio->disconnect();
	}
	else {
		//error input
		fprintf(stderr, "Unknown operation mode.\n");
		return 1;
	}

	timespec tv_2;
	clock_gettime(CLOCK_MONOTONIC,&tv_2);
	printf("The attestation time is: %ld\n", tv_2.tv_sec*1000*1000 + tv_2.tv_nsec/1000 - (tv_1.tv_sec*1000*1000 + tv_1.tv_nsec/1000));

	//close_logfile(fplog);

	return 0;
}

int do_attestation (sgx_enclave_id_t eid, config_t *config)
{
	sgx_status_t status, sgxrv, pse_status;
	sgx_ra_msg1_t msg1;
	sgx_ra_msg2_t *msg2 = NULL;
	sgx_ra_msg3_t *msg3 = NULL;
	ra_msg4_t *msg4 = NULL;
	uint32_t msg0_extended_epid_group_id = 0;
	uint32_t msg3_sz;
	uint32_t flags= config->flags;
	sgx_ra_context_t ra_ctx= 0xdeadbeef;
	int rv;
	MsgIO *msgio;
	size_t msg4sz = 0;
	int enclaveTrusted = NotTrusted; // Not Trusted
	int b_pse= OPT_ISSET(flags, OPT_PSE);

	if ( config->server == NULL ) {
		msgio = new MsgIO();
	} else {
		try {
			msgio = new MsgIO(config->server, (config->port == NULL) ?
				DEFAULT_PORT : config->port);
		}
		catch(...) {
			exit(1);
		}
	}

	/*
	 * WARNING! Normally, the public key would be hardcoded into the
	 * enclave, not passed in as a parameter. Hardcoding prevents
	 * the enclave using an unauthorized key.
	 *
	 * This is diagnostic/test application, however, so we have
	 * the flexibility of a dynamically assigned key.
	 */

	/* Executes an ECALL that runs sgx_ra_init() */ //sgx__ra_init()产生的context是无法更改的

	if ( OPT_ISSET(flags, OPT_PUBKEY) ) {
		if ( debug ) fprintf(stderr, "+++ using supplied public key\n");
		status= enclave_ra_init(eid, &sgxrv, config->pubkey, b_pse,
			&ra_ctx, &pse_status);
	} else {
		if ( debug ) fprintf(stderr, "+++ using default public key\n");
		status= enclave_ra_init_def(eid, &sgxrv, b_pse, &ra_ctx,
			&pse_status);
	}

	/* Did the ECALL succeed? */
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "enclave_ra_init: %08x\n", status);
		delete msgio;
		return 1;
	}

	/* If we asked for a PSE session, did that succeed? */
	if (b_pse) {
		if ( pse_status != SGX_SUCCESS ) {
			fprintf(stderr, "pse_session: %08x\n", sgxrv);
			delete msgio;
			return 1;
		}
	}

	/* Did sgx_ra_init() succeed? */
	if ( sgxrv != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_ra_init: %08x\n", sgxrv);
		delete msgio;
		return 1;
	}

	/* Generate msg0 */

	status = sgx_get_extended_epid_group_id(&msg0_extended_epid_group_id);
	if ( status != SGX_SUCCESS ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx); 
		fprintf(stderr, "sgx_get_extended_epid_group_id: %08x\n", status);
		delete msgio;
		return 1;
	}
 
	/* Generate msg1 */

	status= sgx_ra_get_msg1(ra_ctx, eid, sgx_ra_get_ga, &msg1);
	if ( status != SGX_SUCCESS ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "sgx_ra_get_msg1: %08x\n", status);
		//fprintf(fplog, "sgx_ra_get_msg1: %08x\n", status);
		delete msgio;
		return 1;
	}


	msgio->send_partial(&msg0_extended_epid_group_id,
		sizeof(msg0_extended_epid_group_id));
	msgio->send(&msg1, sizeof(msg1));

	/* Read msg2 
	 *
	 * msg2 is variable length b/c it includes the revocation list at
	 * the end. msg2 is malloc'd in readZ_msg do free it when done.
	 */

	rv= msgio->read((void **) &msg2, NULL);
	if ( rv == 0 ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "protocol error reading msg2\n");
		delete msgio;
		exit(1);
	} else if ( rv == -1 ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "system error occurred while reading msg2\n");
		delete msgio;
		exit(1);
	}


	/* Process Msg2, Get Msg3  */
	/* object msg3 is malloc'd by SGX SDK, so remember to free when finished */

	msg3 = NULL;

	status = sgx_ra_proc_msg2(ra_ctx, eid,
		sgx_ra_proc_msg2_trusted, sgx_ra_get_msg3_trusted, msg2, 
		sizeof(sgx_ra_msg2_t) + msg2->sig_rl_size,
	    &msg3, &msg3_sz);

	free(msg2);

	if ( status != SGX_SUCCESS ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "sgx_ra_proc_msg2: %08x\n", status);
		fprintf(fplog, "sgx_ra_proc_msg2: %08x\n", status);

		delete msgio;
		return 1;
	} 

	msgio->send(msg3, msg3_sz);

	if ( msg3 ) {
		free(msg3);
		msg3 = NULL;
	}
 
	/* Read Msg4 provided by Service Provider, then process */
        
	rv= msgio->read((void **)&msg4, &msg4sz);
	if ( rv == 0 ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "protocol error reading msg4\n");
		delete msgio;
		exit(1);
	} else if ( rv == -1 ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "system error occurred while reading msg4\n");
		delete msgio;
		exit(1);
	}

	//edividerWithText("Enclave Trust Status from Service Provider");

	enclaveTrusted= msg4->status;
	if ( enclaveTrusted == Trusted ) {
		eprintf("Enclave TRUSTED\n");
	}
	else if ( enclaveTrusted == NotTrusted ) {
		eprintf("Enclave NOT TRUSTED\n");
	}
	else if ( enclaveTrusted == Trusted_ItsComplicated ) {
		// Trusted, but client may be untrusted in the future unless it
		// takes action.

		eprintf("Enclave Trust is TRUSTED and COMPLICATED. The client is out of date and\nmay not be trusted in the future depending on the service provider's  policy.\n");
	} else {
		// Not Trusted, but client may be able to take action to become
		// trusted.

		//eprintf("Enclave Trust is NOT TRUSTED and COMPLICATED. The client is out of date.\n");
	}

	/* check to see if we have a PIB by comparing to empty PIB */
	sgx_platform_info_t emptyPIB;
	memset(&emptyPIB, 0, sizeof (sgx_platform_info_t));

	int retPibCmp = memcmp(&emptyPIB, (void *)(&msg4->platformInfoBlob), sizeof (sgx_platform_info_t));

	if (retPibCmp == 0 ) {
		if ( verbose ) eprintf("A Platform Info Blob (PIB) was NOT provided by the IAS\n");
	} else {
		if ( verbose ) eprintf("A Platform Info Blob (PIB) was provided by the IAS\n");

		if ( debug )  {
			eprintf("+++ PIB: " );
			print_hexstring(stderr, &msg4->platformInfoBlob, sizeof (sgx_platform_info_t));
			print_hexstring(fplog, &msg4->platformInfoBlob, sizeof (sgx_platform_info_t));
			eprintf("\n");
		}

		/* We have a PIB, so check to see if there are actions to take */
		sgx_update_info_bit_t update_info;
		sgx_status_t ret = sgx_report_attestation_status(&msg4->platformInfoBlob, 
			enclaveTrusted, &update_info);

		if ( debug )  eprintf("+++ sgx_report_attestation_status ret = 0x%04x\n", ret);
		enclaveTrusted = Trusted;

	}
	free (msg4);

	enclave_ra_close(eid, &sgxrv, ra_ctx);

	char *cert, *encrypted_cert;
	cert = (char*)malloc(sizeof(unsigned char)*40);
	produce_cert_client(eid, (unsigned char*)cert);
	rv= msgio->read((void **)&encrypted_cert, NULL);

	delete msgio;

	return 0;
}

/*
 * Search for the enclave file and then try and load it.
 */
sgx_status_t sgx_create_enclave_search (const char *filename, const int edebug,
	sgx_launch_token_t *token, int *updated, sgx_enclave_id_t *eid,
	sgx_misc_attribute_t *attr)
{
	struct stat sb;
	char epath[PATH_MAX];	/* includes NULL */

	/* Is filename an absolute path? */

	if ( filename[0] == '/' ) 
		return sgx_create_enclave(filename, edebug, token, updated, eid, attr);

	/* Is the enclave in the current working directory? */

	if ( stat(filename, &sb) == 0 )
		return sgx_create_enclave(filename, edebug, token, updated, eid, attr);

	/* Search the paths in LD_LBRARY_PATH */

	if ( file_in_searchpath(filename, getenv("LD_LIBRARY_PATH"), epath, PATH_MAX) )
		return sgx_create_enclave(epath, edebug, token, updated, eid, attr);
		
	/* Search the paths in DT_RUNPATH */

	if ( file_in_searchpath(filename, getenv("DT_RUNPATH"), epath, PATH_MAX) )
		return sgx_create_enclave(epath, edebug, token, updated, eid, attr);

	/* Standard system library paths */

	if ( file_in_searchpath(filename, DEF_LIB_SEARCHPATH, epath, PATH_MAX) )
		return sgx_create_enclave(epath, edebug, token, updated, eid, attr);

	//nothing, then create a new enclave
	return sgx_create_enclave(filename, edebug, token, updated, eid, attr);
}

int file_in_searchpath (const char *file, const char *search, char *fullpath, 
	size_t len)
{
	char *p, *str;
	size_t rem;
	struct stat sb;

	if ( search == NULL ) return 0;
	if ( strlen(search) == 0 ) return 0;

	str= strdup(search);
	if ( str == NULL ) return 0;

	p= strtok(str, ":");
	while ( p != NULL) {
		size_t lp= strlen(p);

		if ( lp ) {

			strncpy(fullpath, p, len-1);
			rem= (len-1)-lp-1;
			fullpath[len-1]= 0;

			strncat(fullpath, "/", rem);
			--rem;

			strncat(fullpath, file, rem);

			if ( stat(fullpath, &sb) == 0 ) {
				free(str);
				return 1;
			}
		}

		p= strtok(NULL, ":");
	}

	free(str);

	return 0;
};


int verify_application(sgx_enclave_id_t src_eid, MsgIO* msgio) {	
	int rv;
	sgx_enclave_id_t dst_eid = 2;
	size_t certificate_sz = 351;
	char *cert, *encrypted_cert;

	msgio->send(certificate, certificate_sz);
	rv = msgio->read((void **)&encrypted_cert, NULL);

	cert = (char*)malloc(sizeof(unsigned char)*40);
	produce_cert_client(dst_eid, (unsigned char*)cert);
	bool authentic = verifySignature(publicKey, cert, encrypted_cert);

	if(authentic) {
		eprintf("Authentication success.\n");
		return 1;
	}
	else {
		eprintf("Authentication fail.\n");
		return 0;
	}
}  

int attestation_fpga(sgx_enclave_id_t eid, int client_sockfd_adapter) {
	uint8_t output[256], msg[256];
	memset(output, 0, 256);
	memset(msg, 0, 256);
	
	uint32_t output_len = (uint32_t)256;
	uint32_t msg_len = (uint32_t)256;
	size_t auth_len = 16*sizeof(int);

	int challenge[16] = {0}, response[16];
	int challenge_2[256];

	sgx_status_t ret = SGX_SUCCESS;
	uint32_t status_tmp = 0;
	char ch_c='o';
	if(send(client_sockfd_adapter, &ch_c, sizeof(ch_c), 0)<=0) {
		perror("Receive session info fail:"); 
		return -1;
	}
	eprintf("connected with FPGA\n");
	//get challenge
	send_auth_to_fpga(eid, &status_tmp, challenge, auth_len);

	eprintf("challenge: \n");
	for(int i=0;i<16;i++) 
		eprintf("%d ", challenge[i]);
	eprintf("\n");

	if(send(client_sockfd_adapter, challenge, sizeof(challenge), 0)<=0)  {
		perror("Receive session info fail:"); 
		return -1;
	}

	if(recv(client_sockfd_adapter, response, auth_len, 0)<=0) {
		perror("Receive response challenge fail:");
		return -1;
	}
	printf("received response from FPGA...\n");

	verify_auth_from_fpga(eid, &status_tmp, response, auth_len);

	if(status_tmp == 0) 
		eprintf("pass fpga authentication.\n");
	//send random sequence
	auth_len = 256*sizeof(int);
	if(send(client_sockfd_adapter, challenge_2, auth_len, 0)<=0) {
		perror("Receive session info fail:"); 
		return -1;
	}
	if(recv(client_sockfd_adapter, output, 256, 0)<=0) {
		perror("Receive encrypted key fail:");
		return -1;
	}

	ret = get_fpga_key(eid, &status_tmp, output, output_len);

	return 1;
};

int ctrl_process_data(sgx_enclave_id_t eid, int client_sockfd_adapter) {
	int sockfd = -1;
    struct sockaddr_un servaddr;
    int result;
    sockfd = socket(AF_LOCAL, SOCK_STREAM, 0);
    unlink(UNIXSTR_PATH);
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sun_family = AF_LOCAL;
    strcpy(servaddr.sun_path, UNIXDP_PATH);
    char ch = ' ';
	eprintf("start to receive data.\n");
    for(;;)
    {   //waiting for connection  
        result = connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr));
        recv(sockfd, &ch, sizeof(ch), 0);
        if(ch=='o') { printf("receive info.\n"); break;}
    }

	uint8_t fpga_message[80000];
	uint32_t status_tmp = 0;
	uint8_t* buffer;
	buffer = (uint8_t*)malloc(sizeof(uint8_t)*80000);
	memset(buffer, 0, 80000);
	//read data
	size_t data_size = 0;
	recv(sockfd, &data_size, sizeof(data_size), 0);
	recv(sockfd, buffer, sizeof(uint8_t)*data_size, 0);

	eprintf("data size: %d\n", data_size);
	size_t data_size_output = data_size;

	uint8_t* recv_data = (uint8_t*)malloc(sizeof(uint8_t)*data_size);
	uint8_t* send_data = (uint8_t*)malloc(sizeof(uint8_t)*data_size_output);

	memset(send_data, 0, data_size_output);
	memcpy(recv_data, buffer, data_size);
	//for(int i=0; i<data_size; i++) eprintf("0x%x ", recv_data[i]);
	//eprintf("\n");
	//process data
	//eprintf("process data\n");
	generate_encrypt_to_fpga_message(eid, &status_tmp, recv_data, data_size, send_data, data_size_output);
	eprintf("send data to fpga. data size: %d\n", data_size_output);
	int size_output = data_size_output;

	// for(int i = 0; i < data_size_output; i++) 
	// 	eprintf("0x%x ", send_data[i]);
	// eprintf("\n");

	//connect to fpga, fpga is on local
	timespec tv_1;
	clock_gettime(CLOCK_MONOTONIC, &tv_1);
	
	if(send(client_sockfd_adapter, &size_output, sizeof(size_output), 0)<=0) 
	{  
		perror("send data size to fpga fail:"); 
		exit(0);
	} 
	
	
	if(send(client_sockfd_adapter, send_data, data_size_output, 0)<=0) 
	{ 
		perror("send data to fpga fail:"); 
		exit(0);
	} 
	//memset(buffer, 0, 70000);
	size_t receive_size;
	if(recv(client_sockfd_adapter, &receive_size, sizeof(int), 0)<=0) 
	{ 
		perror("receive data size from fpga fail:"); 
		exit(0);
	}

	eprintf("receive from fpga size: %d\n", receive_size);


	if(recv(client_sockfd_adapter, fpga_message, receive_size, 0)<=0) 
	{ 
		perror("receive data from fpga fail:"); 
		exit(0);
	} 	
	//send to app
	size_t send_size = receive_size;
	eprintf("send to app size: %d\n", send_size);
	uint8_t* app_message;
	app_message = (uint8_t*)malloc(sizeof(uint8_t)*(send_size));

	//for(int i = 0;i<receive_size;i++) eprintf("0x%x ", fpga_message[i]);
	//eprintf("\n");
	timespec tv_test_2;
	clock_gettime(CLOCK_MONOTONIC, &tv_test_2);
	generate_encrypt_to_app_message(eid, &status_tmp, fpga_message, receive_size, app_message, send_size);
	printf("%ld\n", (tv_test_2.tv_sec*1000*1000 + tv_test_2.tv_nsec/1000)-(tv_1.tv_sec*1000*1000 + tv_1.tv_nsec/1000));
	//FILE *pFile_2;
	//pFile_2 = fopen("send_to_fpga_time.txt", "a");	
	//fprintf(pFile_2, "%ld\n", (tv_test_2.tv_sec*1000*1000 + tv_test_2.tv_nsec/1000)-(tv_test_1.tv_sec*1000*1000 + tv_test_1.tv_nsec/1000));
	//fclose(pFile_2);	
	//for(int i = 0;i<send_size;i++) eprintf("0x%x ", app_message[i]);
	//eprintf("\n");
	//msgio->send((void **) app_message, send_size);
	send(sockfd, &send_size, sizeof(size_t), 0);
	send(sockfd, app_message, sizeof(uint8_t)*send_size, 0);
	
	return 0;
};

int ctrl_process_data_ocall(sgx_enclave_id_t eid, int client_sockfd_adapter)
{
	eprintf("start to send data...\n");
	int sockfd = -1;
    struct sockaddr_un servaddr;
    int result;
    sockfd = socket(AF_LOCAL, SOCK_STREAM, 0);
    unlink(UNIXSTR_PATH);
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sun_family = AF_LOCAL;
    strcpy(servaddr.sun_path, UNIXDP_PATH);
    char ch = ' ';

    for(;;)
    {   //waiting for connection    
        result = connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr));
		//eprintf("start to send data...\n");
        recv(sockfd, &ch, sizeof(ch), 0);
        if(ch=='o') { printf("receive info.\n"); break;}
    }

	uint8_t fpga_message[80000];
	uint32_t status_tmp = 0;
	uint8_t* buffer;
	buffer = (uint8_t*)malloc(sizeof(uint8_t)*80000);
	memset(buffer, 0, 80000);
	//read data
	size_t data_size = 0;
	recv(sockfd, &data_size, sizeof(data_size), 0);
	recv(sockfd, buffer, sizeof(uint8_t)*data_size, 0);
	eprintf("received data size from app: %d\n", data_size);

	
	if(send(client_sockfd_adapter, &data_size, sizeof(int), 0)<=0) 
	{  
		perror("send data size to fpga fail:"); 
		exit(0);
	} 
	
	
	if(send(client_sockfd_adapter, buffer, data_size, 0)<=0) 
	{ 
		perror("send data to fpga fail:"); 
		exit(0);
	} 
	//memset(buffer, 0, 70000);
	size_t receive_size;
	if(recv(client_sockfd_adapter, &receive_size, sizeof(int), 0)<=0) 
	{ 
		perror("receive data size from fpga fail:"); 
		exit(0);
	}

	eprintf("receive from fpga size: %d\n", receive_size);


	if(recv(client_sockfd_adapter, fpga_message, receive_size, 0)<=0) 
	{ 
		perror("receive data from fpga fail:"); 
		exit(0);
	} 	
	//send to app
	
	send(sockfd, &receive_size, sizeof(size_t), 0);
	send(sockfd, fpga_message, sizeof(uint8_t)*receive_size, 0);
	
	return 0;
};


void usage () 
{
	fprintf(stderr, "usage: client [ options ] [ host[:port] ]\n\n");
	fprintf(stderr, "Required:\n");
	fprintf(stderr, "  -N, --nonce-file=FILE    Set a nonce from a file containing a 32-byte\n");
	fprintf(stderr, "                             ASCII hex string\n");
	fprintf(stderr, "  -P, --pubkey-file=FILE   File containing the public key of the service\n");
	fprintf(stderr, "                             provider.\n");
	fprintf(stderr, "  -S, --spid-file=FILE     Set the SPID from a file containing a 32-byte\n");
	fprintf(stderr, "                             ASCII hex string\n");
	fprintf(stderr, "  -d, --debug              Show debugging information\n");
	fprintf(stderr, "  -e, --epid-gid           Get the EPID Group ID instead of performing\n");
	fprintf(stderr, "                             an attestation.\n");
	fprintf(stderr, "  -l, --linkable           Specify a linkable quote (default: unlinkable)\n");
	fprintf(stderr, "  -m, --pse-manifest       Include the PSE manifest in the quote\n");
	fprintf(stderr, "  -n, --nonce=HEXSTRING    Set a nonce from a 32-byte ASCII hex string\n");
	fprintf(stderr, "  -p, --pubkey=HEXSTRING   Specify the public key of the service provider\n");
	fprintf(stderr, "                             as an ASCII hex string instead of using the\n");
	fprintf(stderr, "                             default.\n");
	fprintf(stderr, "  -q                       Generate a quote instead of performing an\n");
	fprintf(stderr, "                             attestation.\n");
	fprintf(stderr, "  -r                       Generate a nonce using RDRAND\n");
	fprintf(stderr, "  -s, --spid=HEXSTRING     Set the SPID from a 32-byte ASCII hex string\n");
	fprintf(stderr, "  -v, --verbose            Print decoded RA messages to stderr\n");
	fprintf(stderr, "  -z                       Read from stdin and write to stdout instead\n");
	fprintf(stderr, "                             connecting to a server.\n");
	fprintf(stderr, "\nOne of --spid OR --spid-file is required for generating a quote or doing\nremote attestation.\n");
	exit(1);
}

