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

#ifndef _WIN32
#include "../config.h"
#endif
#include "Enclave_t.h"
#include <string.h>
#include <sgx_utils.h>
#include <sgx_tkey_exchange.h>
#include <sgx_tcrypto.h>
#include "sgx_dh.h"
#include "sgx_report.h"
#include "sgx_eid.h"
#include "sgx_ecp_types.h"
#include "sgx_tseal.h"

typedef struct _la_dh_session_t
{
    uint32_t  session_id; //Identifies the current session
    uint32_t  status; //Indicates session is in progress, active or closed
    union
    {
        struct
        {
			sgx_dh_session_t dh_session;
        }in_progress;

        struct
        {
            sgx_key_128bit_t AEK; //Session Key
            uint32_t counter; //Used to store Message Sequence Number
        }active;
    };
} dh_session_t;

static const sgx_ec256_public_t def_service_public_key = {
    {
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
    },
    {
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
    }

};

#define PSE_RETRIES	5	/* Arbitrary. Not too long, not too short. */

/*----------------------------------------------------------------------
 * WARNING
 *----------------------------------------------------------------------
 *
 * End developers should not normally be calling these functions
 * directly when doing remote attestation:
 *
 *    sgx_get_ps_sec_prop()
 *    sgx_get_quote()
 *    sgx_get_quote_size()
 *    sgx_get_report()
 *    sgx_init_quote()
 *
 * These functions short-circuits the RA process in order
 * to generate an enclave quote directly!
 *
 * The high-level functions provided for remote attestation take
 * care of the low-level details of quote generation for you:
 *
 *   sgx_ra_init()
 *   sgx_ra_get_msg1
 *   sgx_ra_proc_msg2
 *
 *----------------------------------------------------------------------
 */

/*
 * This doesn't really need to be a C++ source file, but a bug in 
 * 2.1.3 and earlier implementations of the SGX SDK left a stray
 * C++ symbol in libsgx_tkey_exchange.so so it won't link without
 * a C++ compiler. Just making the source C++ was the easiest way
 * to deal with that.
 */

sgx_status_t get_report(sgx_report_t *report, sgx_target_info_t *target_info)
{
#ifdef SGX_HW_SIM
	return sgx_create_report(NULL, NULL, report);
#else
	return sgx_create_report(target_info, NULL, report);
#endif
}



sgx_status_t enclave_ra_init(sgx_ec256_public_t key, int b_pse,
	sgx_ra_context_t *ctx, sgx_status_t *pse_status)
{
	sgx_status_t ra_status;

	/*
	 * If we want platform services, we must create a PSE session 
	 * before calling sgx_ra_init()
	 */


	ra_status= sgx_ra_init(&key, 0, ctx);


	return ra_status;
}

sgx_status_t enclave_ra_init_def(int b_pse, sgx_ra_context_t *ctx,
	sgx_status_t *pse_status)
{
	return enclave_ra_init(def_service_public_key, b_pse, ctx, pse_status);
}



/*
 * Return a SHA256 hash of the requested key. KEYS SHOULD NEVER BE
 * SENT OUTSIDE THE ENCLAVE IN PLAIN TEXT. This function let's us
 * get proof of possession of the key without exposing it to untrusted
 * memory.
 */

uint8_t mkey[16] = {0x19, 0x28, 0x3C, 0x41, 0xB2, 0x5A, 0x31, 0xF8, 
				0xF7, 0xA2, 0x12, 0x0C, 0x9F, 0xAF, 0x31, 0xFD};  //master key in ra
uint8_t skey[16];

/*
 * Return a SHA256 hash of the requested key. KEYS SHOULD NEVER BE
 * SENT OUTSIDE THE ENCLAVE IN PLAIN TEXT. This function let's us
 * get proof of possession of the key without exposing it to untrusted
 * memory.
 */

sgx_status_t enclave_ra_get_key_hash(sgx_status_t *get_keys_ret,
	sgx_ra_context_t ctx, sgx_ra_key_type_t type, sgx_sha256_hash_t *hash)
{
	sgx_status_t sha_ret;
	sgx_ra_key_128_t k;

	// First get the requested key which is one of:
	//  * SGX_RA_KEY_MK 
	//  * SGX_RA_KEY_SK
	// per sgx_ra_get_keys().

	*get_keys_ret= sgx_ra_get_keys(ctx, type, &k);
	if ( *get_keys_ret != SGX_SUCCESS ) return *get_keys_ret;

	/* Now generate a SHA hash */

	sha_ret= sgx_sha256_msg((const uint8_t *) &k, sizeof(k), 
		(sgx_sha256_hash_t *) hash); // Sigh.

	/* Let's be thorough */

	memset(k, 0, sizeof(k));

	return sha_ret;
}

sgx_status_t enclave_ra_close(sgx_ra_context_t ctx)
{
        sgx_status_t ret;
        ret = sgx_ra_close(ctx);
        return ret;
}
/*
uint32_t key_exchange_client_init(sgx_enclave_id_t src_id, sgx_enclave_id_t dest_id)
{
	sgx_dh_msg1_t dh_msg1;            
    sgx_key_128bit_t dh_aek;        
    sgx_dh_msg2_t dh_msg2;            
    sgx_dh_msg3_t dh_msg3;           
    uint32_t session_id;
    uint32_t retstatus;
    sgx_status_t status = SGX_SUCCESS;
    sgx_dh_session_t sgx_dh_session;
    sgx_dh_session_enclave_identity_t responder_identity;
	dh_session_t *session_info;

	if(!session_info)
    {
        return 0xEC; //INVALID_PARAMETER_ERROR
    }

	memset(&dh_aek,0, sizeof(sgx_key_128bit_t));
    memset(&dh_msg1, 0, sizeof(sgx_dh_msg1_t));
    memset(&dh_msg2, 0, sizeof(sgx_dh_msg2_t));
    memset(&dh_msg3, 0, sizeof(sgx_dh_msg3_t));
    memset(session_info, 0, sizeof(dh_session_t));

	status = sgx_dh_init_session(SGX_DH_SESSION_INITIATOR, &sgx_dh_session);
    if(SGX_SUCCESS != status)
    {
            return status;
    }
	//request dh_msg1
	status = dh_session_request_ocall(&retstatus, src_id, dest_id, &dh_msg1, &session_id);
	if (status != SGX_SUCCESS)
    {
        return 0xE5;
    }
	status = sgx_dh_initiator_proc_msg1(&dh_msg1, &dh_msg2, &sgx_dh_session);
    if(SGX_SUCCESS != status)
    {
         return status;
    }
	//send msg2, receive msg3
	status = dh_exchange_report_ocall(&retstatus, src_id, dest_id, &dh_msg2, &dh_msg3, session_id);
    if (status != SGX_SUCCESS)
	{
        return 0xE5;
    }
	//process msg3
	status = sgx_dh_initiator_proc_msg3(&dh_msg3, &sgx_dh_session, &dh_aek, &responder_identity);
    if(SGX_SUCCESS != status)
    {
        return status;
    }

	memcpy(session_info->active.AEK, &dh_aek, sizeof(sgx_key_128bit_t));
    session_info->session_id = session_id;
    session_info->active.counter = 0;
    session_info->status = 0x2; //active
    memset(&dh_aek,0, sizeof(sgx_key_128bit_t));
    return status;
}
*/

#define BUFLEN (650*128)
static uint8_t key_app[16] = {0x19, 0x28, 0x3C, 0x41, 0xB2, 0x5A, 0x31, 0xF8, 
				0xF7, 0xA2, 0x12, 0x0C, 0x9F, 0xAF, 0x31, 0xFD}; 

uint32_t decryptMessage(uint8_t *encMessageIn, size_t len, uint8_t *decMessageOut, size_t lenOut)
{
	if(key_app[0]==0) return -1;
	uint32_t retstatus = 0x01;
	uint8_t *encMessage = (uint8_t *) encMessageIn;
	//emit_debug(encMessage, len);
	uint8_t p_dst[BUFLEN] = {0};
	//lenOut = len - (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE);

	sgx_rijndael128GCM_decrypt(
		&key_app,
		encMessage + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
		lenOut,
		p_dst,
		encMessage, SGX_AESGCM_IV_SIZE,
		encMessage + SGX_AESGCM_IV_SIZE, SGX_AESGCM_MAC_SIZE,
		(sgx_aes_gcm_128bit_tag_t *) (encMessage + lenOut + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE));
	//emit_debug(p_dst, lenOut);
	memcpy(decMessageOut, p_dst, lenOut);
	return retstatus;
};

uint32_t encryptMessage(uint8_t *decMessageIn, size_t len, uint8_t *encMessageOut, size_t lenOut)
{
	if(key_app[0] == 0) return -1; //invalid key
    //uint8_t *origMessage = (uint8_t *) decMessageIn;
	uint8_t p_dst[BUFLEN] = {0};
    uint32_t retstatus = 0x01;
	sgx_read_rand(p_dst, SGX_AESGCM_IV_SIZE);  //iv
	sgx_read_rand(p_dst + SGX_AESGCM_IV_SIZE, SGX_AESGCM_MAC_SIZE);  //mac

	sgx_rijndael128GCM_encrypt(
		&key_app,
		decMessageIn, len, 
		p_dst + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
		p_dst, SGX_AESGCM_IV_SIZE,
		p_dst + SGX_AESGCM_IV_SIZE, SGX_AESGCM_MAC_SIZE,
		(sgx_aes_gcm_128bit_tag_t *) (p_dst + len + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE));	
    //emit_debug(p_dst, lenOut);
	//emit_debug(p_dst, SGX_AESGCM_IV_SIZE);
	//emit_debug(p_dst + SGX_AESGCM_IV_SIZE, SGX_AESGCM_MAC_SIZE);
	//emit_debug(p_dst + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE, len);
	//emit_debug(p_dst + len + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_MAC_SIZE);  //tag size = mac size
	memcpy(encMessageOut,p_dst,lenOut);
    return retstatus;
};

#define SAMPLE_SIZE 128
uint8_t data_sample[SAMPLE_SIZE] = {
    0xA8, 0x87, 0x01, 0xE4, 0x43, 0x4F, 0x59, 0x2D, 0x96, 0xF8, 0x9A, 0x40, 0x29, 0x98, 0x49, 0x57,
    0x99, 0x29, 0x0C, 0x6C, 0xB1, 0xB1, 0x6D, 0x1A, 0x8B, 0x0A, 0x99, 0x29, 0x0C, 0x96, 0x7E, 0xF1,
    0xA8, 0x87, 0x01, 0xE4, 0x43, 0x4F, 0x29, 0x0C, 0x9F, 0xF8, 0x9A, 0x40, 0x29, 0x98, 0x49, 0x57,
    0x99, 0x29, 0x0C, 0x6C, 0xB1, 0xB1, 0x6D, 0x1A, 0x8B, 0x0A, 0xF7, 0xAF, 0x2D, 0x29, 0x0C, 0xF1,
    0xA8, 0xAF, 0x2D, 0x96, 0x43, 0x4F, 0x59, 0x29, 0x0C, 0xF8, 0x9A, 0x40, 0x01, 0xE4, 0x43, 0x57,
    0x99, 0x29, 0x0C, 0x6C, 0xB1, 0x4F, 0x59, 0x2D, 0x96, 0xF8, 0xF7, 0xAF, 0x2D, 0x96, 0x7E, 0xF1,
    0xA8, 0x87, 0x01, 0xE4, 0xB1, 0xB1, 0x6D, 0x1A, 0x8B, 0x0A, 0x9A, 0x40, 0x29, 0x98, 0x49, 0x57,
    0x99, 0x29, 0x0C, 0x6C, 0xB1, 0x4F, 0x29, 0x0C, 0x9F, 0xF8, 0xF7, 0xAF, 0x2D, 0xFD, 0xFE, 0xFF,
    };

uint32_t generate_encrypted_message(uint8_t* data_plain, size_t data_size, uint8_t* data_encrypted, size_t data_size_out, int flag = 0)
{
	//emit_debug(data_plain, data_size);
    uint8_t* ori_msg = (uint8_t*)malloc(sizeof(uint8_t)*data_size);
	uint8_t* enc_msg = (uint8_t*)malloc(sizeof(uint8_t)*data_size_out);
	//memset(ori_msg, 0, data_size);
	memset(enc_msg, 0, data_size_out);
    uint32_t ret = 0;

	if(!flag) //if flag == 0, then copy data inside the enclave
	{	
		for(int i=0; i<data_size/SAMPLE_SIZE; i++)
		{
			if(i*SAMPLE_SIZE < data_size)
				memcpy(ori_msg+i*SAMPLE_SIZE, data_sample, sizeof(uint8_t)*SAMPLE_SIZE);
			else
				memcpy(ori_msg+i*SAMPLE_SIZE, data_sample, sizeof(uint8_t)*(data_size%SAMPLE_SIZE));       
		}
	}
	else 
	{ 
		//receive data from app and encrypt
		memcpy(ori_msg, data_plain, data_size); 
	}
	//emit_debug(ori_msg, data_size);
	//start encryption
    ret = encryptMessage(ori_msg, data_size, enc_msg, data_size_out);
	memcpy(data_encrypted, enc_msg, data_size_out);
	//emit_debug(enc_msg, data_size_out);
	//memcpy(data_encrypted, data_sample, SAMPLE_SIZE);
    free(ori_msg);
	free(enc_msg);

    return ret;
};
/*
uint32_t generate_to_ctrl_message(uint8_t* data_plain, size_t size_plain, uint8_t* data_enc, size_t size_enc)
{
    uint8_t* ori_msg;
	uint8_t* enc_msg;
	enc_msg = (uint8_t*)malloc(sizeof(uint8_t)*size_plain);
    ori_msg = (uint8_t*)malloc(sizeof(uint8_t)*size_enc);
	memcpy(enc_msg, data_plain, size_plain);

	encryptMessage(ori_msg, size_plain, enc_msg, size_enc);

	memcpy(data_enc, enc_msg, size_enc);
	return 0x00;
}
*/

uint32_t generate_decrypted_message(uint8_t* data_encrypted, size_t data_size, size_t data_size_out, uint8_t* data_plain)
{
    uint32_t ret;
    uint8_t* ori_msg;
	uint8_t* enc_msg;
	enc_msg = (uint8_t*)malloc(sizeof(uint8_t)*data_size);
    ori_msg = (uint8_t*)malloc(sizeof(uint8_t)*data_size_out);
	memcpy(enc_msg, data_encrypted, data_size);
	//emit_debug(enc_msg, data_size);
	//start decryption
    ret = decryptMessage(enc_msg, data_size, ori_msg, data_size_out);
	memcpy(data_plain, ori_msg, data_size_out);
	//emit_debug(data_plain, data_size_out);
    free(ori_msg);
    return ret;
}

uint32_t send_encrypetd_message_to_enclave(uint8_t* data_encrypted, size_t data_size)
{
	//emit_debug(data_encrypted, data_size);
	size_t decrypted_data_size = data_size - 28;
	uint8_t* decrypted_message = (uint8_t*)malloc(sizeof(uint8_t)*decrypted_data_size);
	uint8_t* tmp_message = (uint8_t*)malloc(sizeof(uint8_t)*(data_size+10));
	memcpy(tmp_message, data_encrypted, data_size);
	//emit_debug(tmp_message, data_size);
	memset(decrypted_message, 0, decrypted_data_size);

	uint32_t result = decryptMessage(tmp_message, data_size, decrypted_message, decrypted_data_size);
	emit_debug(decrypted_message, decrypted_data_size);
	//free(tmp_message);
	return 0x00;
}

uint32_t generate_plain_message(uint8_t* plain_message, size_t data_size)
{

	for(int i=0; i<data_size/SAMPLE_SIZE; i++)
	{
		if(i*SAMPLE_SIZE < data_size)
			memcpy(plain_message+i*SAMPLE_SIZE, data_sample, sizeof(uint8_t)*SAMPLE_SIZE);
		else
			memcpy(plain_message+i*SAMPLE_SIZE, data_sample, sizeof(uint8_t)*(data_size%SAMPLE_SIZE));       
	}
	return 0X00;
}

uint32_t send_plain_message_to_enclave(uint8_t* plain_message, size_t data_size)
{
	uint8_t* tmp_msg = (uint8_t*)malloc(sizeof(uint8_t)*data_size);
	memcpy(tmp_msg, plain_message, data_size);
	return 0x00;
}