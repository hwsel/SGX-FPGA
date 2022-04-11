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
#include "client.h"

# define ENCLAVE_NAME "Enclave.signed.so"

void emit_debug(const uint8_t *buf, size_t data_size) {
    printf("DEBUG: \n");
    for(int i=0;i<data_size;i++)
    printf("0x%x ", buf[i]);
    printf("\n");
}

int main (int argc, char *argv[]) {

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

	/* Launch the enclave */

	status = sgx_create_enclave_search(ENCLAVE_NAME,
		SGX_DEBUG_FLAG, &token, &updated, &eid, 0);

	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_create_enclave: %s: %08x\n",
			ENCLAVE_NAME, status);
		if ( status == SGX_ERROR_ENCLAVE_FILE_ACCESS ) 
			fprintf(stderr, "Did you forget to set LD_LIBRARY_PATH?\n");
		return 1;
	}

		
#ifdef Time_Eval
		timespec tv_1;
		clock_gettime(CLOCK_MONOTONIC,&tv_1);
#endif
		//attest with server
		// do_attestation(eid, &config); 

#ifdef Time_Eval
		timespec tv_2;
		clock_gettime(CLOCK_MONOTONIC,&tv_2);

		FILE *pFile;
		pFile = fopen("attestation_time.txt", "a");	
		fprintf(pFile, "%ld\n", (tv_2.tv_sec*1000*1000 + tv_2.tv_nsec/1000) - (tv_1.tv_sec*1000*1000 + tv_1.tv_nsec/1000));
		fclose(pFile);
#endif

		net_connector nc;
		nc.server = strdup("localhost");
		MsgIO *msgio;
		msgio = new MsgIO(nc.server, DEFAULT_PORT);
		timespec tv_1;
		clock_gettime(CLOCK_MONOTONIC,&tv_1);
		int result = verify_application(eid, msgio);
		if(result) {	
			//pass verification, send encrypted data to controller
			eprintf("waiting controller...\n");
#ifdef Time_Eval			
			timespec tv_3;
			clock_gettime(CLOCK_MONOTONIC,&tv_3);
#endif
			// start to send data
			data_transmission_trusted_path(DATA_SIZE, eid);
#ifdef Time_Eval
			timespec tv_4;
			clock_gettime(CLOCK_MONOTONIC,&tv_4);
			printf("The transmission time is: %ld\n", tv_4.tv_sec*1000*1000 + tv_4.tv_nsec/1000 - (tv_3.tv_sec*1000*1000 + tv_3.tv_nsec/1000));	
#endif	
		}
		delete msgio;

	/* print time resutls in file
    FILE *pFile;
    pFile = fopen("ra_client.txt", "a");	
	fprintf(pFile, "%ld\t%ld\n", (tv_2.tv_sec*1000*1000 + tv_2.tv_nsec/1000) - (tv_1.tv_sec*1000*1000 + tv_1.tv_nsec/1000), (tv_4.tv_sec*1000*1000 + tv_4.tv_nsec/1000) - (tv_3.tv_sec*1000*1000 + tv_3.tv_nsec/1000));
	fclose(pFile);
	*/
	//timespec tv_2;
	//clock_gettime(CLOCK_MONOTONIC,&tv_2);
	//printf("The attestation time is: %ld\n", tv_2.tv_sec*1000*1000 + tv_2.tv_nsec/1000 - (tv_1.tv_sec*1000*1000 + tv_1.tv_nsec/1000));

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

	/* Executes an ECALL that runs sgx_ra_init() */ 

	if ( OPT_ISSET(flags, OPT_PUBKEY) ) {
		if ( debug ) fprintf(stderr, "+++ using supplied public key\n");
		fprintf(stderr, "+++ using supplied public key\n");
		status= enclave_ra_init(eid, &sgxrv, config->pubkey, b_pse,
			&ra_ctx, &pse_status);
	} else {
		if ( debug ) fprintf(stderr, "+++ using default public key\n");
		fprintf(stderr, "+++ using default public key\n");
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
	if ( verbose ) {
		dividerWithText(stderr, "Msg0 Details");
		//dividerWithText(fplog, "Msg0 Details");
		fprintf(stderr,   "Extended Epid Group ID: ");
		//fprintf(fplog,   "Extended Epid Group ID: ");
		print_hexstring(stderr, &msg0_extended_epid_group_id,
			 sizeof(uint32_t));
		//print_hexstring(fplog, &msg0_extended_epid_group_id,
		//	 sizeof(uint32_t));
		fprintf(stderr, "\n");
		//fprintf(fplog, "\n");
		divider(stderr);
		//divider(fplog);
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

	if ( verbose ) {
		dividerWithText(stderr,"Msg1 Details");
		dividerWithText(fplog,"Msg1 Details");
		fprintf(stderr,   "msg1.g_a.gx = ");
		fprintf(fplog,   "msg1.g_a.gx = ");
		print_hexstring(stderr, msg1.g_a.gx, 32);
		print_hexstring(fplog, msg1.g_a.gx, 32);
		fprintf(stderr, "\nmsg1.g_a.gy = ");
		fprintf(fplog, "\nmsg1.g_a.gy = ");
		print_hexstring(stderr, msg1.g_a.gy, 32);
		print_hexstring(fplog, msg1.g_a.gy, 32);
		fprintf(stderr, "\nmsg1.gid    = ");
		fprintf(fplog, "\nmsg1.gid    = ");
		print_hexstring(stderr, msg1.gid, 4);
		print_hexstring(fplog, msg1.gid, 4);
		fprintf(stderr, "\n");
		fprintf(fplog, "\n");
		divider(stderr);
		divider(fplog);
	}

	/*
	 * Send msg0 and msg1 concatenated together (msg0||msg1). We do
	 * this for efficiency, to eliminate an additional round-trip
	 * between client and server. The assumption here is that most
	 * clients have the correct extended_epid_group_id so it's
	 * a waste to send msg0 separately when the probability of a
	 * rejection is astronomically small.
	 *
	 * If it /is/ rejected, then the client has only wasted a tiny
	 * amount of time generating keys that won't be used.
	 */

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

	if ( verbose ) {
		dividerWithText(stderr, "Msg2 Details");
		dividerWithText(fplog, "Msg2 Details (Received from SP)");
		fprintf(stderr,   "msg2.g_b.gx      = ");
		fprintf(fplog,   "msg2.g_b.gx      = ");
		print_hexstring(stderr, &msg2->g_b.gx, sizeof(msg2->g_b.gx));
		print_hexstring(fplog, &msg2->g_b.gx, sizeof(msg2->g_b.gx));
		fprintf(stderr, "\nmsg2.g_b.gy      = ");
		fprintf(fplog, "\nmsg2.g_b.gy      = ");
		print_hexstring(stderr, &msg2->g_b.gy, sizeof(msg2->g_b.gy));
		print_hexstring(fplog, &msg2->g_b.gy, sizeof(msg2->g_b.gy));
		fprintf(stderr, "\nmsg2.spid        = ");
		fprintf(fplog, "\nmsg2.spid        = ");
		print_hexstring(stderr, &msg2->spid, sizeof(msg2->spid));
		print_hexstring(fplog, &msg2->spid, sizeof(msg2->spid));
		fprintf(stderr, "\nmsg2.quote_type  = ");
		fprintf(fplog, "\nmsg2.quote_type  = ");
		print_hexstring(stderr, &msg2->quote_type, sizeof(msg2->quote_type));
		print_hexstring(fplog, &msg2->quote_type, sizeof(msg2->quote_type));
		fprintf(stderr, "\nmsg2.kdf_id      = ");
		fprintf(fplog, "\nmsg2.kdf_id      = ");
		print_hexstring(stderr, &msg2->kdf_id, sizeof(msg2->kdf_id));
		print_hexstring(fplog, &msg2->kdf_id, sizeof(msg2->kdf_id));
		fprintf(stderr, "\nmsg2.sign_ga_gb  = ");
		fprintf(fplog, "\nmsg2.sign_ga_gb  = ");
		print_hexstring(stderr, &msg2->sign_gb_ga, sizeof(msg2->sign_gb_ga));
		print_hexstring(fplog, &msg2->sign_gb_ga, sizeof(msg2->sign_gb_ga));
		fprintf(stderr, "\nmsg2.mac         = ");
		fprintf(fplog, "\nmsg2.mac         = ");
		print_hexstring(stderr, &msg2->mac, sizeof(msg2->mac));
		print_hexstring(fplog, &msg2->mac, sizeof(msg2->mac));
		fprintf(stderr, "\nmsg2.sig_rl_size = ");
		fprintf(fplog, "\nmsg2.sig_rl_size = ");
		print_hexstring(stderr, &msg2->sig_rl_size, sizeof(msg2->sig_rl_size));
		print_hexstring(fplog, &msg2->sig_rl_size, sizeof(msg2->sig_rl_size));
		fprintf(stderr, "\nmsg2.sig_rl      = ");
		fprintf(fplog, "\nmsg2.sig_rl      = ");
		print_hexstring(stderr, &msg2->sig_rl, msg2->sig_rl_size);
		print_hexstring(fplog, &msg2->sig_rl, msg2->sig_rl_size);
		fprintf(stderr, "\n");
		fprintf(fplog, "\n");
		divider(stderr);
		divider(fplog);
	}

	if ( debug ) {
		fprintf(stderr, "+++ msg2_size = %zu\n",
			sizeof(sgx_ra_msg2_t)+msg2->sig_rl_size);
		fprintf(fplog, "+++ msg2_size = %zu\n",
			sizeof(sgx_ra_msg2_t)+msg2->sig_rl_size);
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

	if ( debug ) {
		fprintf(stderr, "+++ msg3_size = %u\n", msg3_sz);
		fprintf(fplog, "+++ msg3_size = %u\n", msg3_sz);
	}
	                          
	if ( verbose ) {
		dividerWithText(stderr, "Msg3 Details");
		dividerWithText(fplog, "Msg3 Details");
		fprintf(stderr,   "msg3.mac         = ");
		fprintf(fplog,   "msg3.mac         = ");
		print_hexstring(stderr, msg3->mac, sizeof(msg3->mac));
		print_hexstring(fplog, msg3->mac, sizeof(msg3->mac));
		fprintf(stderr, "\nmsg3.g_a.gx      = ");
		fprintf(fplog, "\nmsg3.g_a.gx      = ");
		print_hexstring(stderr, msg3->g_a.gx, sizeof(msg3->g_a.gx));
		print_hexstring(fplog, msg3->g_a.gx, sizeof(msg3->g_a.gx));
		fprintf(stderr, "\nmsg3.g_a.gy      = ");
		fprintf(fplog, "\nmsg3.g_a.gy      = ");
		print_hexstring(stderr, msg3->g_a.gy, sizeof(msg3->g_a.gy));
		print_hexstring(fplog, msg3->g_a.gy, sizeof(msg3->g_a.gy));
		fprintf(stderr, "\nmsg3.ps_sec_prop.sgx_ps_sec_prop_desc = ");
		fprintf(fplog, "\nmsg3.ps_sec_prop.sgx_ps_sec_prop_desc = ");
		print_hexstring(stderr, msg3->ps_sec_prop.sgx_ps_sec_prop_desc,
			sizeof(msg3->ps_sec_prop.sgx_ps_sec_prop_desc));
		print_hexstring(fplog, msg3->ps_sec_prop.sgx_ps_sec_prop_desc,
			sizeof(msg3->ps_sec_prop.sgx_ps_sec_prop_desc));
		fprintf(fplog, "\n");
		fprintf(stderr, "\nmsg3.quote       = ");
		fprintf(fplog, "\nmsg3.quote       = ");
		print_hexstring(stderr, msg3->quote, msg3_sz-sizeof(sgx_ra_msg3_t));
		print_hexstring(fplog, msg3->quote, msg3_sz-sizeof(sgx_ra_msg3_t));
		fprintf(fplog, "\n");
		fprintf(stderr, "\n");
		fprintf(fplog, "\n");
		divider(stderr);
		divider(fplog);
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

	enclaveTrusted = msg4->status;
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

		//for test
		enclaveTrusted = Trusted;
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
			//print_hexstring(fplog, &msg4->platformInfoBlob, sizeof (sgx_platform_info_t));
			eprintf("\n");
		}

		/* We have a PIB, so check to see if there are actions to take */
		sgx_update_info_bit_t update_info;
		sgx_status_t ret = sgx_report_attestation_status(&msg4->platformInfoBlob, 
			enclaveTrusted, &update_info);

		if ( debug )  eprintf("+++ sgx_report_attestation_status ret = 0x%04x\n", ret);

		//edivider();
	}

	/*
	 * If the enclave is trusted, fetch a hash of the the MK and SK from
	 * the enclave to show proof of a shared secret with the service 
	 * provider.
	 */
	/*
	if ( enclaveTrusted == Trusted ) {
		sgx_status_t key_status, sha_status;
		sgx_sha256_hash_t mkhash, skhash;

		// First the MK

		if ( debug ) eprintf("+++ fetching SHA256(MK)\n");
		status= enclave_ra_get_key_hash(eid, &sha_status, &key_status, ra_ctx,
			SGX_RA_KEY_MK, &mkhash);
		if ( debug ) eprintf("+++ ECALL enclage_ra_get_key_hash (MK) ret= 0x%04x\n",
			status);

		if ( debug ) eprintf("+++ sgx_ra_get_keys (MK) ret= 0x%04x\n", key_status);
		// Then the SK

		if ( debug ) eprintf("+++ fetching SHA256(SK)\n");
		status= enclave_ra_get_key_hash(eid, &sha_status, &key_status, ra_ctx,
			SGX_RA_KEY_SK, &skhash);
		if ( debug ) eprintf("+++ ECALL enclage_ra_get_key_hash (MK) ret= 0x%04x\n",
			status);

		if ( debug ) eprintf("+++ sgx_ra_get_keys (MK) ret= 0x%04x\n", key_status);
		if ( verbose ) {
			eprintf("SHA256(MK) = ");
			print_hexstring(stderr, mkhash, sizeof(mkhash));
			print_hexstring(fplog, mkhash, sizeof(mkhash));
			eprintf("\n");
			eprintf("SHA256(SK) = ");
			print_hexstring(stderr, skhash, sizeof(skhash));
			print_hexstring(fplog, skhash, sizeof(skhash));
			eprintf("\n");
		}
	}
	*/
	free (msg4);

	enclave_ra_close(eid, &sgxrv, ra_ctx);

	//generate certificate
	msgio->send(&eid, sizeof(eid));
	char *cert, *encrypted_cert;
	cert = (char*)malloc(sizeof(unsigned char)*40);
	produce_cert_client(eid, (unsigned char*)cert);
	rv= msgio->read((void **)&encrypted_cert, NULL);

	delete msgio;

	return 0;
};

/*
 * Search for the enclave file and then try and load it.
 */

#ifndef _WIN32
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

	/*
	 * If we've made it this far then we don't know where else to look.
	 * Just call sgx_create_enclave() which assumes the enclave is in
	 * the current working directory. This is almost guaranteed to fail,
	 * but it will insure we are consistent about the error codes that
	 * get reported to the calling function.
	 */

	return sgx_create_enclave(filename, edebug, token, updated, eid, attr);
};

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

#endif

int verify_application(sgx_enclave_id_t src_eid, MsgIO* msgio) {	

	int rv;
	sgx_enclave_id_t dst_eid = 2;
	char *cert, *encrypted_cert;
	encrypted_cert = (char*)malloc(351);
	memset(encrypted_cert, 0, 351);
	rv = msgio->read((void **)&encrypted_cert, NULL);
	size_t certificate_sz = 351;
	msgio->send(certificate, certificate_sz);

	cert = (char*)malloc(sizeof(unsigned char)*40);
	produce_cert_client(dst_eid, (unsigned char*)cert);

	if(verifySignature(publicKey, cert, encrypted_cert)) {
		eprintf("Authentication success.\n");
		return 1;
	}
	else  {
		eprintf("Authentication fail.\n");
		return 0;
	}

};

int data_transmission_trusted_path(size_t data_size, sgx_enclave_id_t eid) {

	eprintf("Start to send data to controller, waiting connection...\n");

	int server_sockfd_adapter = -1;
	int client_sockfd_adapter = -1;               
	socklen_t client_adapter_len = sizeof(struct sockaddr);
	struct sockaddr_un server_addr_adapter;
	struct sockaddr_un client_addr_adapter;
	server_sockfd_adapter = socket(AF_LOCAL, SOCK_STREAM, 0);
	unlink(UNIXDP_PATH);
	bzero(&server_addr_adapter, sizeof(server_addr_adapter));
	server_addr_adapter.sun_family = AF_LOCAL;
	strcpy(server_addr_adapter.sun_path, UNIXDP_PATH);
	bind(server_sockfd_adapter, (struct sockaddr*)&server_addr_adapter, sizeof(server_addr_adapter));

	listen(server_sockfd_adapter, 5); 
	while(client_sockfd_adapter == -1) {
		client_sockfd_adapter = accept(server_sockfd_adapter, (struct sockaddr*)&client_addr_adapter, &client_adapter_len); 
	}
	//eprintf("server socket: %d\n", server_sockfd_adapter);
	//eprintf("client socket: %d\n", client_sockfd_adapter);
	//eprintf("connection accepted.\n");

	char ch_c='o';
	if(send(client_sockfd_adapter, &ch_c, sizeof(ch_c), 0)<=0) {
		perror("Receive session info fail:"); 
		return -1;
	}

	uint8_t *plain_text;
	uint8_t *encrypted_text;
	sgx_status_t status = (sgx_status_t)0;
	uint32_t cipher_rv = 0;
	uint8_t* buffer = (uint8_t*)malloc(70000);
	uint8_t* encrypted_message;
	size_t data_receive_size;
	size_t enc_data_size = data_size + 44; //IV = 12, MAC = 16, TAG = 16
	int flag = 1;
	//eprintf("data size: %d\n", data_size);
	//eprintf("enc size: %d\n", enc_data_size);

	plain_text = (uint8_t*)malloc(sizeof(uint8_t)*data_size);

	encrypted_text = (uint8_t*)malloc(sizeof(uint8_t)*(enc_data_size));
	memset(encrypted_text, 0, data_size + 44);

	//core function
#ifdef Time_Eval 
	timespec tv_1;
	clock_gettime(CLOCK_MONOTONIC, &tv_1);
#endif
	status = generate_encrypted_message(eid, &cipher_rv, plain_text, data_size, encrypted_text, enc_data_size, flag);	
	if(status != 0x00 && cipher_rv != 0x01) {
		eprintf("Generating data error.\n");
		return -1;
	}
	
	//printf("Ecall time is: %ld\n", tv_2.tv_sec*1000*1000 + tv_2.tv_nsec/1000 - (tv_1.tv_sec*1000*1000 + tv_1.tv_nsec/1000));
	//eprintf("ecall return value #1: %ld\n", status);	
	//eprintf("ecall return value #2: %ld\n", cipher_rv);
	
	// for(int i = 0; i < enc_data_size; i++)
	// {
	// 	eprintf("0x%x ", encrypted_text[i]);
	// }
	
	
	//msgio->send(encrypted_text, enc_data_size);
	send(client_sockfd_adapter, &enc_data_size, sizeof(size_t), 0);
	send(client_sockfd_adapter, encrypted_text, sizeof(uint8_t)*enc_data_size, 0);

	memset(buffer, 0, 70000);
	recv(client_sockfd_adapter, &data_receive_size, sizeof(size_t), 0);
	recv(client_sockfd_adapter, buffer, sizeof(uint8_t)*data_receive_size, 0);

	size_t true_receive_size = data_receive_size;
	//eprintf("\n");
	eprintf("\nreceive size: %d\n", true_receive_size);
	//for(int i=0;i<true_receive_size;i++) eprintf("0x%x ", buffer[i]);
	//eprintf("\n");
	encrypted_message = (uint8_t*)malloc(sizeof(uint8_t)*true_receive_size);
	memcpy(encrypted_message, buffer, true_receive_size);
	//send_encrypetd_message_to_enclave(eid, &cipher_rv, encrypted_message, true_receive_size);
#ifdef Time_Eval 
	timespec tv_2;
	clock_gettime(CLOCK_MONOTONIC, &tv_2);
	printf("The transmission time is: %ld\n", tv_2.tv_sec*1000*1000 + tv_2.tv_nsec/1000 - (tv_1.tv_sec*1000*1000 + tv_1.tv_nsec/1000));	
	FILE *pFile;
	pFile = fopen("T_time.txt", "a");	
	fprintf(pFile, "%ld\n", tv_2.tv_sec*1000*1000 + tv_2.tv_nsec/1000 - (tv_1.tv_sec*1000*1000 + tv_1.tv_nsec/1000));
	fclose(pFile);
#endif	
	//FILE *pFile;
	//pFile = fopen("on_app.txt", "a");	
	//fprintf(pFile, "%ld\t%ld\n", (tv1.tv_sec*1000*1000 + tv1.tv_nsec/1000)-(tv_1.tv_sec*1000*1000 + tv_1.tv_nsec/1000), (tv_2.tv_sec*1000*1000 + tv_2.tv_nsec/1000) - (tv2.tv_sec*1000*1000 + tv2.tv_nsec/1000));
	//fclose(pFile);
	return 0;
};


int process_data_ocall(size_t data_size, sgx_enclave_id_t eid)
{
	sleep(1);
	
	eprintf("start to send data to controller, waiting connection...\n");

	int server_sockfd_adapter = -1;
	int client_sockfd_adapter = -1;               
	socklen_t client_adapter_len = sizeof(struct sockaddr);
	struct sockaddr_un server_addr_adapter;
	struct sockaddr_un client_addr_adapter;
	server_sockfd_adapter = socket(AF_LOCAL, SOCK_STREAM, 0);
	unlink(UNIXDP_PATH);
	bzero(&server_addr_adapter, sizeof(server_addr_adapter));
	server_addr_adapter.sun_family = AF_LOCAL;
	strcpy(server_addr_adapter.sun_path, UNIXDP_PATH);
	bind(server_sockfd_adapter, (struct sockaddr*)&server_addr_adapter, sizeof(server_addr_adapter));

	listen(server_sockfd_adapter, 5);
	while(client_sockfd_adapter == -1)
	{
		client_sockfd_adapter = accept(server_sockfd_adapter, (struct sockaddr*)&client_addr_adapter, &client_adapter_len); 
	}
	char ch_c='o';
	if(send(client_sockfd_adapter, &ch_c, sizeof(ch_c), 0)<=0) 
	{
		perror("Receive session info fail:"); 
		return -1;
	}
	// timespec tv_1;
	// clock_gettime(CLOCK_MONOTONIC, &tv_1);
	//sample data
	timespec tv_1;
	clock_gettime(CLOCK_MONOTONIC, &tv_1);
	uint8_t *plain_text;
	uint8_t *encrypted_text;
	uint32_t cipher_rv;
	uint8_t* buffer = (uint8_t*)malloc(70000);
	uint8_t* encrypted_message;
	size_t data_receive_size;
	//size_t enc_data_size = (data_size + 44); //IV = 12, MAC = 16, TAG = 16
	int flag = 1;
	
	//memcpy(buffer, &enc_data_size, sizeof(enc_data_size));
	plain_text = (uint8_t*)malloc(sizeof(uint8_t)*data_size);

	//core function
	generate_plain_message(eid, &cipher_rv, plain_text, data_size);	
	/*
	for(int i = 0; i < enc_data_size; i++)
	{
		eprintf("0x%x ", encrypted_text[i]);
	}
	*/
	
	//msgio->send(encrypted_text, enc_data_size);
	send(client_sockfd_adapter, &data_size, sizeof(size_t), 0);
	send(client_sockfd_adapter, plain_text, sizeof(uint8_t)*data_size, 0);

	memset(buffer, 0, 70000);
	//msgio->read((void **) &buffer, &data_receive_size);
	recv(client_sockfd_adapter, &data_receive_size, sizeof(size_t), 0);
	recv(client_sockfd_adapter, buffer, sizeof(uint8_t)*data_receive_size, 0);

	eprintf("receive size: %d\n", data_receive_size);
	//for(int i=0;i<true_receive_size;i++) eprintf("0x%x ", buffer[i]);
	//eprintf("\n");
	uint8_t *plain_message = (uint8_t*)malloc(sizeof(uint8_t)*data_receive_size);
	memcpy(plain_message, buffer, data_receive_size);
	send_plain_message_to_enclave(eid, &cipher_rv, plain_message, data_receive_size);
	timespec tv_2;
	clock_gettime(CLOCK_MONOTONIC, &tv_2);
	FILE *pFile;
	pFile = fopen("on_app_ocall.txt", "a");	
	fprintf(pFile, "%ld\n", (tv_2.tv_sec*1000*1000 + tv_2.tv_nsec/1000)-(tv_1.tv_sec*1000*1000 + tv_1.tv_nsec/1000));
	fclose(pFile);
	return 0;
};


