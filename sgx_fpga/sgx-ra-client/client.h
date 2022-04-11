#include "Enclave_u.h"
#if !defined(SGX_HW_SIM)&&!defined(_WIN32)
#include "sgx_stub.h"
#endif
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
#include "hexutil.h"
#include "fileio.h"
#include "base64.h"
#include "crypto.h"
#include "msgio.h"
#include "logfile.h"
#include "quote_size.h"

#define MAX_LEN 80
#define DATA_SIZE (128)

# define _rdrand64_step(x) ({ unsigned char err; asm volatile("rdrand %0; setc %1":"=r"(*x), "=qm"(err)); err; })
#define DEF_LIB_SEARCHPATH "/lib:/lib64:/usr/lib:/usr/lib64"
#define UNIXDP_PATH "/tmp/unix.make"

typedef struct config_struct {
	char mode;
	uint32_t flags;
	sgx_spid_t spid;
	sgx_ec256_public_t pubkey;
	sgx_quote_nonce_t nonce;
	char *server;
	char *port;
} config_t;

typedef struct net_connector {
	char *server;
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

char certificate[351] = "W8+cDyhKnmqqA0RU/mu9xEouJFDwhrr69JI6KYthwbQ9aMppf/YQQbjGipMqR0PU\n"\
"MuhFYBXAhdZL0V2dxQi0ja7vrE8DUqosITLc2ftuqUfr/aQqxSHWLWn0sKGEnkXZ\n"\
"txZY8SnaTYuykeG2b29HycKXc9SO4RIgXJ9YdhHGYZX4JkvQQq+p5SbZkbc6+A4o\n"\
"fokJBJZoeDDXlFhM168T7LICslvVFZPA7XkCcw+pZf+erk5eb2s+/HTyM0oT+iEJ\n"\
"3Fow54bcZ9mjSTQfzeJk1WogmN+STmMiKnYZDil80dH7GJVWy5kN9RotFDhtTxOf\n"\
"PV/uhv/MkTC5krZ9QfX5bQ==\n";

uint8_t data_sample[128] = {
0xA8, 0x87, 0x01, 0xE4, 0x43, 0x4F, 0x59, 0x2D, 0x96, 0xF8, 0x9A, 0x40, 0x29, 0x98, 0x49, 0x57,
0x99, 0x29, 0x0C, 0x6C, 0xB1, 0xB1, 0x6D, 0x1A, 0x8B, 0x0A, 0x99, 0x29, 0x0C, 0x96, 0x7E, 0xF1,
0xA8, 0x87, 0x01, 0xE4, 0x43, 0x4F, 0x29, 0x0C, 0x9F, 0xF8, 0x9A, 0x40, 0x29, 0x98, 0x49, 0x57,
0x99, 0x29, 0x0C, 0x6C, 0xB1, 0xB1, 0x6D, 0x1A, 0x8B, 0x0A, 0xF7, 0xAF, 0x2D, 0x29, 0x0C, 0xF1,
0xA8, 0xAF, 0x2D, 0x96, 0x43, 0x4F, 0x59, 0x29, 0x0C, 0xF8, 0x9A, 0x40, 0x01, 0xE4, 0x43, 0x57,
0x99, 0x29, 0x0C, 0x6C, 0xB1, 0x4F, 0x59, 0x2D, 0x96, 0xF8, 0xF7, 0xAF, 0x2D, 0x96, 0x7E, 0xF1,
0xA8, 0x87, 0x01, 0xE4, 0xB1, 0xB1, 0x6D, 0x1A, 0x8B, 0x0A, 0x9A, 0x40, 0x29, 0x98, 0x49, 0x57,
0x99, 0x29, 0x0C, 0x6C, 0xB1, 0x4F, 0x29, 0x0C, 0x9F, 0xF8, 0xF7, 0xAF, 0x2D, 0xFD, 0xFE, 0xFF,
};

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

int do_quote (sgx_enclave_id_t eid, config_t *config);
int do_attestation (sgx_enclave_id_t eid, config_t *config);
int data_transmission_trusted_path (size_t data_size, sgx_enclave_id_t eid);
int verify_application(sgx_enclave_id_t src_eid, MsgIO* msgio);
int process_data_ocall(size_t data_size, sgx_enclave_id_t eid);

char debug = 0;
char verbose = 0;

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

// #define Time_Eval true