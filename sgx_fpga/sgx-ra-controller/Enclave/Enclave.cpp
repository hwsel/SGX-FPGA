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

#include "rsa.h"
#include "keys.h"
#include "aes_gcm.h"

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

uint8_t rand_ral[16] = {0};
uint8_t session_key[16] = {0};  //encrypt key

static uint8_t password[16] = {0x19, 0x28, 0x3C, 0x41, 0xB2, 0x5A, 0x31, 0xF8, 
				0xF7, 0xA2, 0x12, 0x0C, 0x9F, 0xAF, 0x31, 0xFD};
static uint8_t prime[16] = {0x0B, 0x25, 0x35, 0x3B, 0x25, 0x1D, 0x2B, 0x13,
				0x17, 0x2B, 0x1D, 0x43, 0x25, 0x35, 0x29, 0x0D};   //n

#define PSE_RETRIES	5	/* Arbitrary. Not too long, not too short. */

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
};

/*
 * Return a SHA256 hash of the requested key. KEYS SHOULD NEVER BE
 * SENT OUTSIDE THE ENCLAVE IN PLAIN TEXT. This function let's us
 * get proof of possession of the key without exposing it to untrusted
 * memory.
 */

uint8_t mkey[16] = {0x19, 0x28, 0x3C, 0x41, 0xB2, 0x5A, 0x31, 0xF8, 
				0xF7, 0xA2, 0x12, 0x0C, 0x9F, 0xAF, 0x31, 0xFD};  //master key in ra
uint8_t skey[16];

sgx_status_t enclave_ra_get_key_hash(sgx_status_t *get_keys_ret,
	sgx_ra_context_t ctx, sgx_ra_key_type_t type, sgx_sha256_hash_t *hash)
{
	sgx_status_t sha_ret;
	sgx_ra_key_128_t k;

	*get_keys_ret= sgx_ra_get_keys(ctx, type, &k);
	if ( *get_keys_ret != SGX_SUCCESS ) return *get_keys_ret;

	//copy the master/mask key to the variable "key" (to encrypt future messages)
	if(type == SGX_RA_KEY_SK) 
	{
		memcpy(skey, k, 16);
		emit_debug(skey, sizeof(skey));
	}
	else
	{
		memcpy(mkey, k, 16);
		emit_debug(mkey, sizeof(mkey));		
	}
	sha_ret= sgx_sha256_msg((const uint8_t *) &k, sizeof(k), 
		(sgx_sha256_hash_t *) hash); 

	memset(k, 0, sizeof(k));

	return sha_ret;
}

sgx_status_t enclave_ra_close(sgx_ra_context_t ctx)
{
        sgx_status_t ret;
        ret = sgx_ra_close(ctx);
        return ret;
}

//key is here. The key is app-controller key
#define BUFLEN (650*128)
static uint8_t key_app[16] = {0x19, 0x28, 0x3C, 0x41, 0xB2, 0x5A, 0x31, 0xF8, 
				0xF7, 0xA2, 0x12, 0x0C, 0x9F, 0xAF, 0x31, 0xFD}; 

uint32_t decryptMessage(uint8_t* key, uint8_t *encMessageIn, size_t len, uint8_t *decMessageOut, size_t lenOut)
{
	if(key[0]==0) return -1;
	static uint8_t local_key[16];
	memcpy(local_key, key, 16);
	uint8_t *encMessage = (uint8_t *) encMessageIn;
	//emit_debug(encMessage, len);
	uint8_t p_dst[BUFLEN] = {0};
	//lenOut = len - (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE);

	sgx_rijndael128GCM_decrypt(
		&local_key,
		encMessage + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
		lenOut,
		p_dst,
		encMessage, SGX_AESGCM_IV_SIZE,
		encMessage + SGX_AESGCM_IV_SIZE, SGX_AESGCM_MAC_SIZE,
		(sgx_aes_gcm_128bit_tag_t *) (encMessage + lenOut + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE));
	//emit_debug(p_dst, lenOut);
	memcpy(decMessageOut, p_dst, lenOut);
};

uint32_t encryptMessage(uint8_t* key, uint8_t *decMessageIn, size_t len, uint8_t *encMessageOut, size_t lenOut)
{
	if(key[0] == 0) return -1; //invalid key
	static uint8_t local_key[16];
	memcpy(local_key, key, 16);
    //uint8_t *origMessage = (uint8_t *) decMessageIn;
	size_t encrypted_len = len + 44;
	if(encrypted_len != lenOut)
		return 0x01; //fail, error size output

	uint8_t p_dst[BUFLEN] = {0};
    uint32_t retstatus;
	sgx_read_rand(p_dst, SGX_AESGCM_IV_SIZE);  //iv
	sgx_read_rand(p_dst + SGX_AESGCM_IV_SIZE, SGX_AESGCM_MAC_SIZE);  //mac

	sgx_rijndael128GCM_encrypt(
		&local_key,
		decMessageIn, len, 
		p_dst + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
		p_dst, SGX_AESGCM_IV_SIZE,
		p_dst + SGX_AESGCM_IV_SIZE, SGX_AESGCM_MAC_SIZE,
		(sgx_aes_gcm_128bit_tag_t *) (p_dst + len + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE));	
    
	memcpy(encMessageOut, p_dst, encrypted_len);
    return retstatus;
};

uint32_t generate_decrypted_message(uint8_t* data_encrypted, size_t data_size, size_t data_size_out, uint8_t* data_plain)
{
    uint32_t ret;
    uint8_t* ori_msg;
	uint8_t* enc_msg;
	enc_msg = (uint8_t*)malloc(sizeof(uint8_t)*data_size);
    ori_msg = (uint8_t*)malloc(sizeof(uint8_t)*data_size_out);
	memcpy(enc_msg, data_encrypted, data_size);
	//start decryption
    ret = decryptMessage(key_app, enc_msg, data_size, ori_msg, data_size_out);
	memcpy(data_plain, ori_msg, data_size_out);
	//emit_debug(data_plain, data_size_out);
    free(ori_msg);
    return ret;
};



uint32_t generate_encrypt_to_fpga_message(uint8_t *MessageIn, size_t len, uint8_t *encMessageOut, size_t lenOut)
{
	size_t plain_text_len = len-44;
	uint8_t *decMessage = (uint8_t*)malloc(sizeof(uint8_t)*lenOut);
	uint8_t *encMessage = (uint8_t*)malloc(sizeof(uint8_t)*lenOut);
	uint8_t *test_encMessage = (uint8_t*)malloc(sizeof(uint8_t)*len);
	uint8_t *tag = (uint8_t*)malloc(sizeof(uint8_t)*16);
	//decrypt
	decryptMessage(key_app, MessageIn, len, decMessage, plain_text_len);
	//emit_debug(decMessage, plain_text_len);

	//uint8_t auth_msg[16] = {0x98, 0x87, 0x76, 0x65, 0x54, 0x43, 0x32, 0x21, 0x10, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7};
	//uint8_t iv[12] = {0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC};
	//encryption
	//int aes_gcm_encryption(uint8_t* key, uint8_t* data, uint8_t* auth_msg, uint8_t* iv, size_t hexlen, uint8_t* cipher_text, uint8_t* tag);
	//aes_gcm_encryption(decMessage, session_key, auth_msg, iv, plain_text_len, encMessage, tag);
	encryptMessage(key_app, decMessage, plain_text_len, encMessage, len);
	//emit_debug(encMessage, plain_text_len);
	//copy data 
	/*
	memcpy(encMessageOut, iv, 12);
	memcpy(encMessageOut+12, auth_msg, 16);
	memcpy(encMessageOut+28, encMessage, plain_text_len);
	memcpy(encMessageOut+plain_text_len+28, tag, 16);
	*/
	memcpy(encMessageOut, encMessage, len);
	//emit_debug(test_encMessage, len);
	//emit_debug(encMessageOut, lenOut);
	
	free(decMessage);
	free(encMessage);
	free(tag);
    return 0x00;
}

uint32_t generate_encrypt_to_app_message(uint8_t *MessageIn, size_t len, uint8_t *encMessageOut, size_t lenOut)
{
	//emit_debug(MessageIn, len);
	//emit_debug(session_key, 16);
	size_t plain_len = (len - 44);
	size_t encrypted_len = lenOut;
	uint8_t* encrypted_message = (uint8_t*)malloc(sizeof(uint8_t)*plain_len);
	uint8_t* plain_message = (uint8_t*)malloc(sizeof(uint8_t)*plain_len);
	/*
	uint8_t* iv = (uint8_t*)malloc(sizeof(uint8_t)*12);
	uint8_t* mac = (uint8_t*)malloc(sizeof(uint8_t)*16);
	uint8_t* tag = (uint8_t*)malloc(sizeof(uint8_t)*16);
	memcpy(iv, MessageIn, 12);
	//emit_debug(iv, 12);
	memcpy(mac, MessageIn + 12, 16);
	memcpy(encrypted_message, MessageIn + 28, plain_len);
	memcpy(tag, MessageIn + plain_len + 28, 16);
	memcpy(encMessageOut, MessageIn, lenOut);
	*/
	//emit_debug(encrypted_message, plain_len);
	//decrypt message from fpga
	decryptMessage(key_app, MessageIn, len, plain_message, plain_len);
	//int result = aes_gcm_decryption(encrypted_message, session_key, mac, iv, tag, plain_len, plain_message);
	//if(result != 0) 
	//	return 0x01; //decryption fail
	//emit_debug(plain_message, plain_len);
	//encrypt message and send to app	
	uint8_t* encrypted_message_to_app = (uint8_t*)malloc(sizeof(uint8_t)*lenOut);
	encryptMessage(key_app, plain_message, plain_len, encrypted_message_to_app, lenOut);
	//uint8_t* decrypted_message_to_app = (uint8_t*)malloc(sizeof(uint8_t)*plain_len);
	//decryptMessage(encrypted_message_to_app, lenOut, decrypted_message_to_app, plain_len);
	//emit_debug(encrypted_message_to_app, plain_len);
	memcpy(encMessageOut, encrypted_message_to_app, lenOut);

	free(encrypted_message_to_app);
	free(encrypted_message);
	free(plain_message);
	/*
	free(iv);
	free(mac);
	free(tag);
	*/

	return  0x00;

}

void set_sk(rsa_sk_t *sk)
{
    sk->bits = KEY_M_BITS;
    memcpy(&sk->modulus         [RSA_MAX_MODULUS_LEN-sizeof(key_m) ],  key_m,  sizeof(key_m ));
    memcpy(&sk->public_exponet  [RSA_MAX_MODULUS_LEN-sizeof(key_e) ],  key_e,  sizeof(key_e ));
    memcpy(&sk->exponent        [RSA_MAX_MODULUS_LEN-sizeof(key_pe)],  key_pe, sizeof(key_pe));
    memcpy(&sk->prime1          [RSA_MAX_PRIME_LEN - sizeof(key_p1)],  key_p1, sizeof(key_p1));
    memcpy(&sk->prime2          [RSA_MAX_PRIME_LEN - sizeof(key_p2)],  key_p2, sizeof(key_p2));
    memcpy(&sk->prime_exponent1 [RSA_MAX_PRIME_LEN - sizeof(key_e1)],  key_e1, sizeof(key_e1));
    memcpy(&sk->prime_exponent2 [RSA_MAX_PRIME_LEN - sizeof(key_e2)],  key_e2, sizeof(key_e2));
    memcpy(&sk->coefficient     [RSA_MAX_PRIME_LEN - sizeof(key_c) ],  key_c,  sizeof(key_c ));
}

void set_pk(rsa_pk_t *pk)
{
    pk->bits = KEY_M_BITS;
    memcpy(&pk->modulus         [RSA_MAX_MODULUS_LEN-sizeof(key_m) ],  key_m,  sizeof(key_m ));
    memcpy(&pk->exponent        [RSA_MAX_MODULUS_LEN-sizeof(key_e) ],  key_e,  sizeof(key_e ));
}

uint32_t rsa_encryption(uint8_t* input, uint32_t input_len, uint8_t* output, uint32_t output_len)
{
	rsa_pk_t pk = {0};
	set_pk(&pk);
    rsa_public_encrypt(output, &output_len, input, input_len, &pk);
	return 0;
}

uint32_t rsa_decryption(uint8_t* input, uint32_t input_len, uint8_t* output, uint32_t output_len)
{
	rsa_sk_t sk = {0};
	set_sk(&sk);
	rsa_private_decrypt(output, &output_len, input, input_len, &sk);
	return 0;
}

uint32_t get_fpga_key(uint8_t* input, uint32_t input_len)
{
	int key_len = 16;
	rsa_decryption(input, input_len, session_key, key_len);
	//emit_debug(session_key, 16);
	if(key_len != 16) return -2;
	else if(session_key[0] == 0) return -1;
	else return 0;
}

/* THE FOLLOWING FUNCTIONS ONLY FOR TEST AND DEBUG*/

/* Import key from app */
uint32_t get_negotiation_key(uint8_t* key_in, size_t key_size)
{
	memcpy(session_key, key_in, key_size);
	return 0;
};

int ori_auth[256] = {1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1,
					1, 0, 1, 0 ,1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1,
					1, 0, 1, 0 ,1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1,
					1, 0, 1, 0 ,1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1,
					1, 0, 1, 0 ,1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1,
					1, 0, 1, 0 ,1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1,
					1, 0, 1, 0 ,1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1,
					1, 0, 1, 0 ,1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1,
					1, 0, 1, 0 ,1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1,
					1, 0, 1, 0 ,1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1,
					1, 0, 1, 0 ,1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1,
					1, 0, 1, 0 ,1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1,
					1, 0, 1, 0 ,1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1,
					1, 0, 1, 0 ,1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1,
					1, 0, 1, 0 ,1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1,
					1, 0, 1, 0 ,1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1};

uint32_t send_auth_to_fpga(int* auth, size_t auth_len)
{
	memcpy(auth, ori_auth, auth_len);
}

uint32_t verify_auth_from_fpga(int* auth, size_t auth_len)
{
	int ori_auth[16] = {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};
	int result = memcmp(ori_auth, auth, auth_len);
	return (uint32_t)result;
}
