
#include "aes_gcm.h"

uint8_t R1[128] = { 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, };

int cmpArr(uint8_t *X, uint8_t *Y, int length){
	int i;
	for (i = 0; i < length; i++){
		if (X[i] == Y[i])
			continue;
		else
			return 0;
	}
	return 1;
}


uint8_t GF(uint8_t a, uint8_t b){
	uint8_t p = 0, i, c;

	for (i = 0; i < 8; i++) {
		if (b & 1)
			p ^= a;
		c = a & 0x80;
		a <<= 1;
		if (c)
			a ^= 0x1B;
		b >>= 1;
	}

	return (uint8_t)p;
}

void Add(uint8_t a[], uint8_t b[], uint8_t d[]){

	d[0] = a[0] ^ b[0];
	d[1] = a[1] ^ b[1];
	d[2] = a[2] ^ b[2];
	d[3] = a[3] ^ b[3];

}

void Multi(uint8_t *a, uint8_t *b, uint8_t *d){

	d[0] = GF(a[0], b[0]) ^ GF(a[3], b[1]) ^ GF(a[2], b[2]) ^ GF(a[1], b[3]);
	d[1] = GF(a[1], b[0]) ^ GF(a[0], b[1]) ^ GF(a[3], b[2]) ^ GF(a[2], b[3]);
	d[2] = GF(a[2], b[0]) ^ GF(a[1], b[1]) ^ GF(a[0], b[2]) ^ GF(a[3], b[3]);
	d[3] = GF(a[3], b[0]) ^ GF(a[2], b[1]) ^ GF(a[1], b[2]) ^ GF(a[0], b[3]);

}

void Subuint8_ts(uint8_t *state) {

	uint8_t i;
	for (i = 0; i < 16; i++) {
		state[i] = SBox[state[i]];

	}
}

void ShiftRows(uint8_t *state) {

	int s = 0;
	uint8_t tmp;

	for (int i = 1; i < 4; i++) {
		s = 0;
		while (s < i) {
			tmp = state[4 * i + 0];

			for (int k = 1; k < 4; k++) {
				state[4 * i + k - 1] = state[4 * i + k];
			}

			state[4 * i + 4 - 1] = tmp;
			s++;
		}
	}
}

void MixColums(uint8_t *state) {

	uint8_t a[] = { 0x02, 0x01, 0x01, 0x03 };
	uint8_t col[4], res[4];
	int i = 0, j = 0;

	for (j = 0; j < 4; j++) {
		for (i = 0; i < 4; i++) {
			col[i] = state[4 * i + j];
		}

		Multi(a, col, res);

		for (i = 0; i < 4; i++) {
			state[4 * i + j] = res[i];
		}
	}
}

void AddRoundKey(uint8_t *state, uint8_t *w, int r) {

	for (int c = 0; c < 4; c++) {
		state[4 * 0 + c] = state[4 * 0 + c] ^ w[16 * r + 4 * c + 0];
		state[4 * 1 + c] = state[4 * 1 + c] ^ w[16 * r + 4 * c + 1];
		state[4 * 2 + c] = state[4 * 2 + c] ^ w[16 * r + 4 * c + 2];
		state[4 * 3 + c] = state[4 * 3 + c] ^ w[16 * r + 4 * c + 3];
	}
}


void Sub(uint8_t *w) {

	for (int i = 0; i < 4; i++) {
		w[i] = SBox[16 * ((w[i] & 0xf0) >> 4) + (w[i] & 0x0f)];
	}
}

void Rot(uint8_t *w) {

	uint8_t tmp;

	tmp = w[0];
	for (int i = 0; i < 3; i++) {
		w[i] = w[i + 1];
	}
	w[3] = tmp;
}


uint8_t R[] = { 0x02, 0x00, 0x00, 0x00 };

uint8_t * Rcon(int i) {

	if (i == 1) {
		R[0] = 0x01;
	}
	else if (i > 1) {
		R[0] = 0x02;
		i--;
		while (i - 1 > 0) {
			R[0] = GF(R[0], 0x02);
			i--;
		}
	}
	return R;
}

void KeyExpansion(uint8_t *key, uint8_t *w) {

	uint8_t tmp[4];
	int i;
	int len = 4 * (10 + 1);

	for (i = 0; i < 4; i++) {
		w[4 * i + 0] = key[4 * i + 0];
		w[4 * i + 1] = key[4 * i + 1];
		w[4 * i + 2] = key[4 * i + 2];
		w[4 * i + 3] = key[4 * i + 3];
	}

	for (i = 4; i < len; i++) {
		tmp[0] = w[4 * (i - 1) + 0];
		tmp[1] = w[4 * (i - 1) + 1];
		tmp[2] = w[4 * (i - 1) + 2];
		tmp[3] = w[4 * (i - 1) + 3];

		if (i % 4 == 0) {
			Rot(tmp);
			Sub(tmp);
			Add(tmp, Rcon(i / 4), tmp);

		}

		w[(4 * i) + 0] = w[4 * (i - 4) + 0] ^ tmp[0];
		w[(4 * i) + 1] = w[4 * (i - 4) + 1] ^ tmp[1];
		w[(4 * i) + 2] = w[4 * (i - 4) + 2] ^ tmp[2];
		w[(4 * i) + 3] = w[4 * (i - 4) + 3] ^ tmp[3];
	}
}

void Encrypt(uint8_t *PlainText, uint8_t *CipherText, uint8_t *w) {

	uint8_t state[4 * 4];
	int r, i, j;

	for (i = 0; i < 4; i++) {
		for (j = 0; j < 4; j++) {
			state[4 * i + j] = PlainText[i + 4 * j];
		}
	}

	AddRoundKey(state, w, 0);

	for (r = 1; r < 10; r++) {  //10 rounds
		Subuint8_ts(state);
		ShiftRows(state);
		MixColums(state);
		AddRoundKey(state, w, r);
	}
	Subuint8_ts(state);
	ShiftRows(state);
	AddRoundKey(state, w, 10);

	for (i = 0; i < 4; i++) {
		for (j = 0; j < 4; j++) {
			CipherText[i + 4 * j] = state[4 * i + j];
		}
	}
}

void cpystr(uint8_t * X, uint8_t *Y, int len){
	int i;
	for (i = 0; i < len; i++){
		X[i] = Y[i];
	}
}

void Multiplication(uint8_t *X, uint8_t *Y){
	// X , Y 
	// Output = X
	int val = 0, pow = 128;
	uint8_t x1[128], Z[128] = { 0x00 }, V[128];
	uint8_t prv_Z[128] = { 0x00 }, prv_V[128];
	int i, j, k;
	for (i = 0; i < 16; i++){		// X denote
		for (j = 0; j < 8; j++){
			x1[i * 8 + (7 - j)] = X[i] % 2;
			X[i] = X[i] / 2;
		}
	}
	for (i = 0; i < 16; i++){		// Y denote
		for (j = 0; j < 8; j++){
			V[i * 8 + (7 - j)] = Y[i] % 2;
			Y[i] = Y[i] / 2;
		}
	}
	for (k = 0; k < 128; k++){
		prv_V[k] = V[k];
	}
	//======================================== Complete↓
	for (i = 0; i < 128; i++){
		//calc Zi+1 
		if (x1[i] == 0){
			//zi+1 = zi
		}
		else{
			for (j = 0; j < 128; j++){
				Z[j] = prv_Z[j] ^ prv_V[j];
			}
		}
		//calc Vi+1 
		if (prv_V[127] == 0){
			V[0] = 0;
			for (j = 1; j < 128; j++){
				V[j] = prv_V[j - 1];
			}
		}
		else{
			V[0] = 0;
			for (j = 1; j < 128; j++){
				V[j] = prv_V[j - 1];
			}
			for (j = 0; j < 128; j++){
				V[j] = V[j] ^ R1[j];
			}
		}
		for (j = 0; j < 128; j++){
			prv_V[j] = V[j];
			prv_Z[j] = Z[j];
		}
	}
	//=======================================================
	for (i = 0; i < 16; i++){
		for (j = 0; j < 8; j++){
			val += Z[i * 8 + j] * pow;
			pow /= 2;
		}
		X[i] = val;
		val = 0;
		pow = 128;
	}
}
void inc32(uint8_t *X){  //complete
	int i;
	int xlen = 96;
	uint8_t temp[12];
	uint8_t tamp[4];
	unsigned int d = 0;
	for (i = 0; i < 12; i++){
		temp[i] = X[i];
	}

	for (i = 12; i < 16; i++){
		tamp[i - 12] = X[i];
	}

	for (i = 0; i < 4; i++){
		d += tamp[i] * pow((double)256, (3 - i));
	}
	d++;
	d = d % 0x100000000;

	for (i = 0; i < 4; i++){
		tamp[3 - i] = d % 256;
		d /= 256;
	}
	for (i = 0; i < 12; i++){
		X[i] = temp[i];
	}
	for (i = 12; i < 16; i++){
		X[i] = tamp[i - 12];
	}
}
void GCTR(int length, uint8_t *m, uint8_t *Y, uint8_t *ICB, uint8_t *ekey, int fin){
	// hexlen , n , m ,Y (output) , ICB , ekey(AES key expansion) , fin : firstCTR 0 , lastCTR 1
	int i, j, k, nowlen;
	uint8_t x1[16] = { 0, }, y1[16] = { 0, };
	uint8_t ICB_temp[16] = { 0, }, CIPH[16] = { 0, };
	nowlen = length;
	int round = length / 16 + 1;
	for (i = 0; i < round; i++){
		if (nowlen >= 16){
			for (k = 0; k < 16; k++){
				x1[k] = 0;
				y1[k] = 0;
			}
			for (j = 0; j < 16; j++){
				x1[j] = m[i * 16 + j];
			}
			if (fin == 0)
				inc32(ICB);  // ICB_temp -> ICB
			Encrypt(ICB, CIPH, ekey);
			for (k = 0; k < 16; k++){
				y1[k] = x1[k] ^ CIPH[k];
			}
			//printf("\n");
			for (k = 0; k < 16; k++){
				Y[i * 16 + k] = y1[k];
			}
			nowlen -= 16;
		}
		else if (nowlen >0 && nowlen < 16){
			for (k = 0; k < 16; k++){
				x1[k] = 0;
				y1[k] = 0;
			}
			for (j = 0; j < nowlen; j++){
				x1[j] = m[i * 16 + j];
			}

			inc32(ICB);  // ICB_temp -> ICB
			Encrypt(ICB, CIPH, ekey);
			for (k = 0; k < nowlen; k++){
				y1[k] = x1[k] ^ CIPH[k];
			}
			for (k = 0; k < nowlen; k++){
				Y[i * 16 + k] = y1[k];
			}

		}
	}
}
int GHASH(int length, uint8_t *X1, uint8_t *Y1, uint8_t *ekey){
	int i, j, n;
	uint8_t zero[16] = { 0, };
	uint8_t tmpY[16] = { 0, };
	uint8_t tamp[16];
	uint8_t H[16] = { 0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e };
	n = length / 16;
	if (length * 8 < 128 || (length * 8) % 128 != 0){
		return -1;
	}
	for (i = 0; i < n; i++){

		for (j = 0; j < 16; j++){
			tamp[j] = X1[i * 16 + j];
		}
		for (j = 0; j < 16; j++){
			Y1[j] = tmpY[j] ^ tamp[j];
		}
		Encrypt(zero, H, ekey);
		Multiplication(Y1, H);
		for (j = 0; j < 16; j++){
			tmpY[j] = Y1[j];
		}
	}
	return 0;
}

int makeN(int length)
{  //number of blocks
	int n;
	if (length * 4 % 128 == 0)
		n = length * 4 / 128;
	else
		n = length * 4 / 128 + 1;

	return n;
}
void gerJ0(uint8_t *iv, uint8_t *j, uint8_t *ekey, int n){
	//IV j IVhexlen;
	int i = 0, s, IVlen, k = 0;
	uint8_t *ivtmp, lenIV[8];

	//printf("%d\n", strlen(iv));
	if (n == 12){
		for (i = 0; i < 12; i++)
			j[i] = iv[i];
		for (i = 12; i < 15; i++)
			j[i] = 0;
		j[15] = 1;
	}
	else{
		IVlen = n * 8; 
		for (i = 0; i < 8; i++){
			lenIV[7 - i] = IVlen % 256;
			IVlen /= 256;
		}
		IVlen = n * 8;
		s = 128 * makeN(n * 2) - IVlen;
		// n + 8*makeN(n*2) + 16;
		ivtmp = (uint8_t*)malloc(sizeof(uint8_t)*((IVlen + s + 64 + 64) / 8) + 1);
		memset(ivtmp, 0, (IVlen + s + 64 + 64) / 8 + 1);
		for (i = 0; i < n; i++){
			ivtmp[i] = iv[i];
		}
		for (i = n; i < n + (s + 64) / 8; i++){
			ivtmp[i] = 0x00;
		}
		for (i = n + (s + 64) / 8; i < n + (s / 8) + 8 + 8; i++){
			ivtmp[i] = lenIV[k];
			k++;
		}
		GHASH((IVlen + s + 64 + 64) / 8, ivtmp, j, ekey);
	}
}
int padding(uint8_t *Y, uint8_t *A, int C_size, int A_size){ //
	//size is hex size , need *8
	uint8_t lenC[8]; uint8_t lenA[8];
	uint8_t *tamp;
	int len;
	int cBlen = C_size * 8, aBlen = A_size * 8;
	int max = 16, max2 = 0, i = 0, j = 0, k = 0, val;
	if (A == NULL)
		max2 = 0;
	else
		max2 = 16;

	while (C_size > max){
		max += 16;
	}
	while ((A_size > max2) && (A_size != 0)){
		max2 += 16;
	}
	tamp = (uint8_t*)malloc(sizeof(uint8_t)*(max + 3));
	//=======================================
	for (i = 0; i < 8; i++){
		lenC[7 - i] = cBlen % 256;
		cBlen /= 256;
	}								// [len(A)]64 || [len(C)]64
	for (i = 0; i < 8; i++){
		lenA[7 - i] = aBlen % 256;
		aBlen /= 256;
	}
	//=======================================C padding
	for (i = C_size; i < max; i++){
		Y[i] = 0x00;
	}
	for (i = 0; i < max; i++){
		tamp[i] = Y[i];
	}
	if (A == NULL){
		//======================================= [len(A)]64 || [len(C)]64
		for (i = max; i < max + 8; i++){
			Y[i] = lenA[j];
			j++;
		}
		for (i = max + 8; i < max + 16; i++){
			Y[i] = lenC[k];
			k++;
		}
		val = max + 16;
	}
	else{
		//=================================== A padding
		for (i = 0; i < A_size; i++){
			Y[i] = A[i];
		}
		for (i = A_size; i < max2; i++){
			Y[i] = 0x00;
		}
		//==================================== C padding
		for (i = max2; i < max2 + max; i++){
			Y[i] = tamp[k];
			k++;
		}
		k = 0; j = 0;
		//===================================== lenC lenA
		for (i = max2 + max; i < max2 + max + 8; i++){
			Y[i] = lenA[j];
			j++;
		}
		for (i = max2 + max + 8; i < max2 + max + 16; i++){
			Y[i] = lenC[k];
			k++;
		}
		val = max2 + max + 16;
	}
	return val;
}

int aes_gcm_encryption(uint8_t* data, uint8_t* key, uint8_t* auth_msg, uint8_t* iv, size_t hexlen, uint8_t* cipher_text, uint8_t* tag)
{
	uint8_t * X; 
	uint8_t * Y; 
	uint8_t *m = 0; //message
	uint8_t *A = 0; //mac
	int n, len;
	uint8_t J0[16] = { 0, }, ICB[16] = { 0 };

	uint8_t *IV = 0;
	uint8_t ekey[4 * 44] = { 0, };
	//plain text
	uint8_t* plain_text = (uint8_t*)malloc(sizeof(uint8_t)*hexlen);
	m = (uint8_t *)malloc(sizeof(uint8_t)*hexlen);
	memcpy(m, data, hexlen);
	memcpy(plain_text, m, hexlen);
	//mac
	A = (uint8_t *)malloc(sizeof(uint8_t)*AESGCM_MAC_SIZE);
	memcpy(A, auth_msg, AESGCM_MAC_SIZE);
	uint8_t* mac = (uint8_t*)malloc(sizeof(uint8_t)*AESGCM_MAC_SIZE);
	memcpy(mac, A, AESGCM_MAC_SIZE);
	//iv
	IV = (uint8_t *)malloc(sizeof(uint8_t)*AESGCM_IV_SIZE);
	memcpy(IV, iv, AESGCM_IV_SIZE);
	
	Y = (uint8_t *)realloc(plain_text, sizeof(uint8_t)*hexlen + AESGCM_MAC_SIZE + 1);
	X = (uint8_t *)realloc(mac, sizeof(uint8_t)*hexlen + AESGCM_MAC_SIZE + 1);
	//compute cipher text
	KeyExpansion(key, ekey);
	gerJ0(IV, J0, ekey, AESGCM_IV_SIZE);
	cpystr(ICB, J0, 16);
	GCTR(hexlen, m, Y, ICB, ekey, 0);
	memcpy(cipher_text, Y, hexlen);
	//generate tag
	len = padding(Y, A, hexlen, AESGCM_MAC_SIZE);
	GHASH(len, Y, X, ekey);
	GCTR(16, X, Y, J0, ekey, 1);
	memcpy(tag, Y, 16);
	return 0;
}

//decrypt
int aes_gcm_decryption(uint8_t *tmp_msg, uint8_t* key, uint8_t *auth_msg, uint8_t *iv, uint8_t *tag, size_t hexlen, uint8_t* plain_text)
{
	uint8_t * X; uint8_t * Y; uint8_t *C1 = 0; uint8_t *T1 = 0; uint8_t *P = 0;
	int n, len;
	uint8_t J0[16] = { 0, }, ICB[16] = { 0 };
	uint8_t *IV = 0;
	uint8_t ekey[4 * 44] = { 0, };
	//plain_text data
	uint8_t* C = (uint8_t *)malloc(sizeof(uint8_t)*hexlen);
	memcpy(C, tmp_msg, hexlen);
	//mac
	uint8_t* A = (uint8_t *)malloc(sizeof(uint8_t)*AESGCM_MAC_SIZE);
	memcpy(A, auth_msg, AESGCM_MAC_SIZE);
	//iv
	IV = (uint8_t *)malloc(sizeof(uint8_t)*AESGCM_IV_SIZE);
	memcpy(IV, iv, AESGCM_IV_SIZE);
	//tag
	uint8_t* T = (uint8_t *)malloc(sizeof(uint8_t)*AESGCM_TAG_SIZE);
	memcpy(T, tag, AESGCM_TAG_SIZE);

	T1 = (uint8_t *)malloc(sizeof(uint8_t)*(AESGCM_TAG_SIZE + 1));
	C1 = (uint8_t *)malloc(sizeof(uint8_t)*hexlen + AESGCM_MAC_SIZE + 1);
	Y = (uint8_t *)malloc(sizeof(uint8_t)*hexlen + AESGCM_MAC_SIZE + 1);
	X = (uint8_t *)malloc(sizeof(uint8_t)*hexlen + AESGCM_MAC_SIZE + 1);
	P = (uint8_t *)malloc(sizeof(uint8_t)*hexlen + AESGCM_MAC_SIZE + 1);

	memset(T1, 0, AESGCM_TAG_SIZE + 1);
	memset(C1, 0, hexlen + AESGCM_MAC_SIZE + 1);

	KeyExpansion(key, ekey);
	gerJ0(IV, J0, ekey, AESGCM_IV_SIZE);   
	cpystr(ICB, J0, 16);  
	GCTR(hexlen, C, Y, ICB, ekey, 0); 
	cpystr(P, Y, hexlen);  
	cpystr(C1, C, hexlen);  
	len = padding(C1, A, hexlen, AESGCM_MAC_SIZE);  
	GHASH(len, C1, X, ekey); 
	GCTR(16, X, Y, J0, ekey, 1);
	cpystr(T1, Y, 16);  
	if (cmpArr(T,T1, AESGCM_TAG_SIZE)){
		//success
		memcpy(plain_text, P, hexlen);
	}
	else{
		//fail
		return -1;
	}

	return 0;
}
/*
int main(int argc, char *argv[])
{
	uint8_t data[128] = {0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90, 0xA1, 0xA2, 0xB1, 0xB2, 0xC1, 0xC2, 0xC3,
						0x49, 0x23, 0x43, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90, 0xA1, 0xA2, 0xB1, 0xB2, 0xC1, 0xC2, 0xC3,
						0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90, 0xA1, 0xA2, 0xB1, 0xB2, 0xC1, 0xC2, 0xC3,
						0x49, 0x23, 0x43, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90, 0xA1, 0xA2, 0xB1, 0xB2, 0xC1, 0xC2, 0xC3,
						0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90, 0xA1, 0xA2, 0xB1, 0xB2, 0xC1, 0xC2, 0xC3,
						0x49, 0x23, 0x43, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90, 0xA1, 0xA2, 0xB1, 0xB2, 0xC1, 0xC2, 0xC3,
						0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90, 0xA1, 0xA2, 0xB1, 0xB2, 0xC1, 0xC2, 0xC3,
						0x49, 0x23, 0x43, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90, 0xA1, 0xA2, 0xB1, 0xB2, 0xC1, 0xC2, 0xC3};
	uint8_t auth_msg[16] = {0x98, 0x87, 0x76, 0x65, 0x54, 0x43, 0x32, 0x21, 0x10, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7};
	uint8_t iv[12]={0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC};
	size_t data_len = 128;
	int result;
	//save computation results
	uint8_t buffer[MAX_LEN] = {0};
	uint8_t computated_tag[16] = {0};
	uint8_t plain_text[128] = {0};

	//encrypt
	result = aes_gcm_encryption(data, auth_msg, iv, data_len, buffer, computated_tag);
	printf("encrypted message: \n");
	for(int i=0;i<data_len;i++) printf("0x%x ", buffer[i]);
	printf("\ntag: \n");
	for(int i=0;i<AESGCM_TAG_SIZE;i++) printf("0x%x ", computated_tag[i]);
	printf("\n");
	//decrypt
	result = aes_gcm_decryption(buffer, auth_msg, iv, computated_tag, data_len, plain_text);
	printf("\nplain text: \n");
	for(int i=0;i<data_len;i++) printf("0x%x ", plain_text[i]);
	printf("\n");
	return 0;

}*/