#pragma OPENCL EXTENSION cl_khr_fp64 : enable

typedef ulong dbn_t;
typedef uint bn_t;
typedef uchar uint8_t;
typedef uint uint32_t;
typedef ulong uint64_t;
typedef double real_t;

#define BN_DIGIT_BITS               32      // For uint32_t
#define BN_MAX_DIGITS               65      // RSA_MAX_MODULUS_LEN + 1

#define BN_MAX_DIGIT                0xFFFFFFFF

#define DIGIT_2MSB(x)               (uint32_t)(((x) >> (BN_DIGIT_BITS - 2)) & 0x03)


void bn_decode(bn_t *bn, uint32_t digits, uint8_t *hexarr, uint32_t size);
void bn_encode(uint8_t *hexarr, uint32_t size, bn_t *bn, uint32_t digits);

void bn_assign(bn_t *a, bn_t *b, uint32_t digits);                                          // a = b
void bn_assign_zero(bn_t *a, uint32_t digits);                                              // a = 0

bn_t bn_add(bn_t *a, bn_t *b, bn_t *c, uint32_t digits);                                    // a = b + c, return carry
bn_t bn_sub(bn_t *a, bn_t *b, bn_t *c, uint32_t digits);                                    // a = b - c, return borrow
void bn_mul(bn_t *a, bn_t *b, bn_t *c, uint32_t digits);                                    // a = b * c
void bn_div(bn_t *a, bn_t *b, bn_t *c, uint32_t cdigits, bn_t *d, uint32_t ddigits);        // a = b / c, d = b % c
bn_t bn_shift_l(bn_t *a, bn_t *b, uint32_t c, uint32_t digits);                             // a = b << c (a = b * 2^c)
bn_t bn_shift_r(bn_t *a, bn_t *b, uint32_t c, uint32_t digits);                             // a = b >> c (a = b / 2^c)

void bn_mod(bn_t *a, bn_t *b, uint32_t bdigits, bn_t *c, uint32_t cdigits);                 // a = b mod c
void bn_mod_mul(bn_t *a, bn_t *b, bn_t *c, bn_t *d, uint32_t digits);                       // a = b * c mod d
void bn_mod_exp(bn_t *a, bn_t *b, bn_t *c, uint32_t cdigits, bn_t *d, uint32_t ddigits);    // a = b ^ c mod d

int bn_cmp(bn_t *a, bn_t *b, uint32_t digits);                                              // returns sign of a - b

uint32_t bn_digits(bn_t *a, uint32_t digits);   

#define BN_ASSIGN_DIGIT(a, b, digits)   {bn_assign_zero(a, digits); a[0] = b;}
//end of bignum.h

//start of bignum.cpp
static bn_t bn_sub_digit_mul(bn_t *a, bn_t *b, bn_t c, bn_t *d, uint32_t digits);
static bn_t bn_add_digit_mul(bn_t *a, bn_t *b, bn_t c, bn_t *d, uint32_t digits);
static uint32_t bn_digit_bits(bn_t a);

void bn_decode(bn_t *bn, uint32_t digits, uint8_t *hexarr, uint32_t size)
{
    bn_t t;
    int j;
    uint32_t i, u;
    for(i=0,j=size-1; i<digits && j>=0; i++) {
        t = 0;
        for(u=0; j>=0 && u<BN_DIGIT_BITS; j--, u+=8) {
            t |= ((bn_t)hexarr[j]) << u;
        }
        bn[i] = t;
    }

    for(; i<digits; i++) {
        bn[i] = 0;
    }
}

void bn_encode(uint8_t *hexarr, uint32_t size, bn_t *bn, uint32_t digits)
{
    bn_t t;
    int j;
    uint32_t i, u;

    for(i=0,j=size-1; i<digits && j>=0; i++) {
        t = bn[i];
        for(u=0; j>=0 && u<BN_DIGIT_BITS; j--, u+=8) {
            hexarr[j] = (uint8_t)(t >> u);
        }
    }

    for(; j>=0; j--) {
        hexarr[j] = 0;
    }
}

void bn_assign(bn_t *a, bn_t *b, uint32_t digits)
{
    uint32_t i;
    for(i=0; i<digits; i++) {
        a[i] = b[i];
    }
}

void bn_assign_zero(bn_t *a, uint32_t digits)
{
    uint32_t i;
    for(i=0; i<digits; i++) {
        a[i] = 0;
    }
}

bn_t bn_add(bn_t *a, bn_t *b, bn_t *c, uint32_t digits)
{
    bn_t ai, carry;
    uint32_t i;

    carry = 0;
    for(i=0; i<digits; i++) {
        if((ai = b[i] + carry) < carry) {
            ai = c[i];
        } else if((ai += c[i]) < c[i]) {
            carry = 1;
        } else {
            carry = 0;
        }
        a[i] = ai;
    }

    return carry;
}

bn_t bn_sub(bn_t *a, bn_t *b, bn_t *c, uint32_t digits)
{
    bn_t ai, borrow;
    uint32_t i;

    borrow = 0;
    for(i=0; i<digits; i++) {
        if((ai = b[i] - borrow) > (BN_MAX_DIGIT - borrow)) {
            ai = BN_MAX_DIGIT - c[i];
        } else if((ai -= c[i]) > (BN_MAX_DIGIT - c[i])) {
            borrow = 1;
        } else {
            borrow = 0;
        }
        a[i] = ai;
    }

    return borrow;
}

void bn_mul(bn_t *a, bn_t *b, bn_t *c, uint32_t digits)
{
    bn_t t[2*BN_MAX_DIGITS];
    uint32_t bdigits, cdigits, i;

    bn_assign_zero(t, 2*digits);
    bdigits = bn_digits(b, digits);
    cdigits = bn_digits(c, digits);

    for(i=0; i<bdigits; i++) {
        t[i+cdigits] += bn_add_digit_mul(&t[i], &t[i], b[i], c, cdigits);
    }

    bn_assign(a, t, 2*digits);

    // Clear potentially sensitive information
    //memset((uint8_t *)t, 0, sizeof(t));
    for(int i=0;i<2*BN_MAX_DIGITS;i++) t[i]=0;
}

void bn_div(bn_t *a, bn_t *b, bn_t *c, uint32_t cdigits, bn_t *d, uint32_t ddigits)
{
    dbn_t tmp;
    bn_t ai, t, cc[2*BN_MAX_DIGITS+1], dd[BN_MAX_DIGITS];
    int i;
    uint32_t dddigits, shift;

    dddigits = bn_digits(d, ddigits);
    if(dddigits == 0)
        return;

    shift = BN_DIGIT_BITS - bn_digit_bits(d[dddigits-1]);
    bn_assign_zero(cc, dddigits);
    cc[cdigits] = bn_shift_l(cc, c, shift, cdigits);
    bn_shift_l(dd, d, shift, dddigits);
    t = dd[dddigits-1];

    bn_assign_zero(a, cdigits);
    i = cdigits - dddigits;
    for(; i>=0; i--) {
        if(t == BN_MAX_DIGIT) {
            ai = cc[i+dddigits];
        } else {
            tmp = cc[i+dddigits-1];
            tmp += (dbn_t)cc[i+dddigits] << BN_DIGIT_BITS;
            ai = tmp / (t + 1);
        }

        cc[i+dddigits] -= bn_sub_digit_mul(&cc[i], &cc[i], ai, dd, dddigits);
        // printf("cc[%d]: %08X\n", i, cc[i+dddigits]);
        while(cc[i+dddigits] || (bn_cmp(&cc[i], dd, dddigits) >= 0)) {
            ai++;
            cc[i+dddigits] -= bn_sub(&cc[i], &cc[i], dd, dddigits);
        }
        a[i] = ai;
        // printf("ai[%d]: %08X\n", i, ai);
    }

    bn_assign_zero(b, ddigits);
    bn_shift_r(b, cc, shift, dddigits);

    // Clear potentially sensitive information
    for(int i=0;i<2*BN_MAX_DIGITS+1;i++)
    {
        cc[i]=0;
        if(i<2*BN_MAX_DIGITS) dd[i]=0;
    }
    //memset((uint8_t *)cc, 0, sizeof(cc));
    //memset((uint8_t *)dd, 0, sizeof(dd));
}

bn_t bn_shift_l(bn_t *a, bn_t *b, uint32_t c, uint32_t digits)
{
    bn_t bi, carry;
    uint32_t i, t;

    if(c >= BN_DIGIT_BITS)
        return 0;

    t = BN_DIGIT_BITS - c;
    carry = 0;
    for(i=0; i<digits; i++) {
        bi = b[i];
        a[i] = (bi << c) | carry;
        carry = c ? (bi >> t) : 0;
    }

    return carry;
}

bn_t bn_shift_r(bn_t *a, bn_t *b, uint32_t c, uint32_t digits)
{
    bn_t bi, carry;
    int i;
    uint32_t t;

    if(c >= BN_DIGIT_BITS)
        return 0;

    t = BN_DIGIT_BITS - c;
    carry = 0;
    i = digits - 1;
    for(; i>=0; i--) {
        bi = b[i];
        a[i] = (bi >> c) | carry;
        carry = c ? (bi << t) : 0;
    }

    return carry;
}

void bn_mod(bn_t *a, bn_t *b, uint32_t bdigits, bn_t *c, uint32_t cdigits)
{
    bn_t t[2*BN_MAX_DIGITS] = {0};

    bn_div(t, a, b, bdigits, c, cdigits);

    // Clear potentially sensitive information
    for(int i=0;i<2*BN_MAX_DIGITS;i++) t[i]=0;
    //memset((uint8_t *)t, 0, sizeof(t));
}

void bn_mod_mul(bn_t *a, bn_t *b, bn_t *c, bn_t *d, uint32_t digits)
{
    bn_t t[2*BN_MAX_DIGITS];

    bn_mul(t, b, c, digits);
    bn_mod(a, t, 2*digits, d, digits);

    // Clear potentially sensitive information
    for(int i=0;i<2*BN_MAX_DIGITS;i++) t[i]=0;
    //memset((uint8_t *)t, 0, sizeof(t));
}

void bn_mod_exp(bn_t *a, bn_t *b, bn_t *c, uint32_t cdigits, bn_t *d, uint32_t ddigits) //cdigits -> edigits; ndigits -> ddigits
{
    bn_t bpower_1[BN_MAX_DIGITS], bpower_2[BN_MAX_DIGITS], bpower_3[BN_MAX_DIGITS];
    bn_t ci, t[BN_MAX_DIGITS];
    int i;
    uint32_t ci_bits, j, s;

    bn_assign(bpower_1, b, ddigits);
    bn_mod_mul(bpower_2, bpower_1, b, d, ddigits);
    bn_mod_mul(bpower_3, bpower_2, b, d, ddigits);   

    BN_ASSIGN_DIGIT(t, 1, ddigits);

    cdigits = bn_digits(c, cdigits);
    i = cdigits - 1;
    for(; i>=0; i--) 
    {
        ci = c[i];
        ci_bits = BN_DIGIT_BITS;

        if(i == (int)(cdigits - 1)) 
        {
            while(!DIGIT_2MSB(ci)) 
            {
                ci <<= 2;
                ci_bits -= 2;
            }
        }

        for(j=0; j<ci_bits; j+=2) 
        {
            bn_mod_mul(t, t, t, d, ddigits);
            bn_mod_mul(t, t, t, d, ddigits);
            s = DIGIT_2MSB(ci);
            if(s != 0) 
            {
                if(s == 1)
                    bn_mod_mul(t, t, bpower_1, d, ddigits);
                else if(s == 2)
                    bn_mod_mul(t, t, bpower_2, d, ddigits);
                else if(s == 3)
                    bn_mod_mul(t, t, bpower_3, d, ddigits);
            }
            ci <<= 2;
        }
    }

    bn_assign(a, t, ddigits);
    
}

int bn_cmp(bn_t *a, bn_t *b, uint32_t digits)
{
    int i;
    for(i=digits-1; i>=0; i--) {
        if(a[i] > b[i])     return 1;
        if(a[i] < b[i])     return -1;
    }

    return 0;
}

uint32_t bn_digits(bn_t *a, uint32_t digits)
{
    int i;
    for(i=digits-1; i>=0; i--) {
        if(a[i])    break;
    }

    return (i + 1);
}

static bn_t bn_add_digit_mul(bn_t *a, bn_t *b, bn_t c, bn_t *d, uint32_t digits)
{
    dbn_t result;
    bn_t carry, rh, rl;
    uint32_t i;

    if(c == 0)
        return 0;

    carry = 0;
    for(i=0; i<digits; i++) {
        result = (dbn_t)c * d[i];
        rl = result & BN_MAX_DIGIT;
        rh = (result >> BN_DIGIT_BITS) & BN_MAX_DIGIT;
        if((a[i] = b[i] + carry) < carry) {
            carry = 1;
        } else {
            carry = 0;
        }
        if((a[i] += rl) < rl) {
            carry++;
        }
        carry += rh;
    }

    return carry;
}

static bn_t bn_sub_digit_mul(bn_t *a, bn_t *b, bn_t c, bn_t *d, uint32_t digits)
{
    dbn_t result;
    bn_t borrow, rh, rl;
    uint32_t i;

    if(c == 0)
        return 0;

    borrow = 0;
    for(i=0; i<digits; i++) {
        result = (dbn_t)c * d[i];
        rl = result & BN_MAX_DIGIT;
        rh = (result >> BN_DIGIT_BITS) & BN_MAX_DIGIT;
        if((a[i] = b[i] - borrow) > (BN_MAX_DIGIT - borrow)) {
            borrow = 1;
        } else {
            borrow = 0;
        }
        if((a[i] -= rl) > (BN_MAX_DIGIT - rl)) {
            borrow++;
        }
        borrow += rh;
    }

    return borrow;
}

static uint32_t bn_digit_bits(bn_t a)
{
    uint32_t i;
    for(i=0; i<BN_DIGIT_BITS; i++) {
        if(a == 0)  break;
        a >>= 1;
    }

    return i;
}
//end of bignum.cpp

//start of rsa.h

#define RSA_MAX_MODULUS_BITS                2048
#define RSA_MAX_MODULUS_LEN                 ((RSA_MAX_MODULUS_BITS + 7) / 8)
#define RSA_MAX_PRIME_BITS                  ((RSA_MAX_MODULUS_BITS + 1) / 2)
#define RSA_MAX_PRIME_LEN                   ((RSA_MAX_PRIME_BITS + 7) / 8)

// Error codes
#define ERR_WRONG_DATA                      0x1001
#define ERR_WRONG_LEN                       0x1002

typedef struct {
    uint32_t bits;
    uint8_t  modulus[RSA_MAX_MODULUS_LEN];
    uint8_t  exponent[RSA_MAX_MODULUS_LEN];
} rsa_pk_t;

typedef struct {
    uint32_t bits;
    uint8_t  modulus[RSA_MAX_MODULUS_LEN];
    uint8_t  public_exponet[RSA_MAX_MODULUS_LEN];
    uint8_t  exponent[RSA_MAX_MODULUS_LEN];
    uint8_t  prime1[RSA_MAX_PRIME_LEN];
    uint8_t  prime2[RSA_MAX_PRIME_LEN];
    uint8_t  prime_exponent1[RSA_MAX_PRIME_LEN];
    uint8_t  prime_exponent2[RSA_MAX_PRIME_LEN];
    uint8_t  coefficient[RSA_MAX_PRIME_LEN];
} rsa_sk_t;

int rsa_public_encrypt (uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_pk_t *pk);
int rsa_public_decrypt (uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_pk_t *pk);
int rsa_private_encrypt(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_sk_t *sk);
int rsa_private_decrypt(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_sk_t *sk);

//end of rsa.h

//start of rsa.cpp
static int public_block_operation(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_pk_t *pk);
static int private_block_operation(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_sk_t *sk);

__global static uint8_t rnd_seed;

void set_rnd_seed(uint8_t new_seed)
{
	rnd_seed = new_seed;
}

uint8_t rand_uint8()
{
	uint8_t k1;
	uint8_t ix=rnd_seed;
	k1 = ix/12773;
	ix=16807*(ix-k1*127773)-k1*2836;
	if(ix<0) ix+=2147483647;
	rnd_seed=ix;
	return rnd_seed;
}

int rsa_public_encrypt(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_pk_t *pk)
{
    int status;
    uint8_t byte, pkcs_block[RSA_MAX_MODULUS_LEN];
    uint32_t i, modulus_len;

    modulus_len = (pk->bits + 7) / 8;
    if(in_len + 11 > modulus_len) {
        return ERR_WRONG_LEN;
    }

    pkcs_block[0] = 0;
    pkcs_block[1] = 2;

    set_rnd_seed(in[0]);

    for(i=2; i<modulus_len-in_len-1; i++) {
        do {
            byte = rand_uint8();
        } while(byte == 0);
        pkcs_block[i] = byte;
    }

    pkcs_block[i++] = 0;
    for(int j=0;j<in_len; j++) pkcs_block[i+j] = in[j];
    //memcpy((uint8_t *)&pkcs_block[i], (uint8_t *)in, in_len);
    status = public_block_operation(out, out_len, pkcs_block, modulus_len, pk);

    // Clear potentially sensitive information
    byte = 0;
    for(int j=0;j<RSA_MAX_MODULUS_LEN; j++) pkcs_block[j] = 0;
    //memset((uint8_t *)pkcs_block, 0, sizeof(pkcs_block));

    return status;
}

int rsa_public_decrypt(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_pk_t *pk)
{
    int status;
    uint8_t pkcs_block[RSA_MAX_MODULUS_LEN];
    uint32_t i, modulus_len, pkcs_block_len;

    modulus_len = (pk->bits + 7) / 8;
    if(in_len > modulus_len)
        return ERR_WRONG_LEN;

    status = public_block_operation(pkcs_block, &pkcs_block_len, in, in_len, pk);
    if(status != 0)
        return status;

    if(pkcs_block_len != modulus_len)
        return ERR_WRONG_LEN;

    if((pkcs_block[0] != 0) || (pkcs_block[1] != 1))
        return ERR_WRONG_DATA;

    for(i=2; i<modulus_len-1; i++) {
        if(pkcs_block[i] != 0xFF)   break;
    }

    if(pkcs_block[i++] != 0)
        return ERR_WRONG_DATA;

    *out_len = modulus_len - i;
    if(*out_len + 11 > modulus_len)
        return ERR_WRONG_DATA;

    for(int j=0; j<*out_len; j++) out[j] = pkcs_block[j+i];
    //memcpy((uint8_t *)out, (uint8_t *)&pkcs_block[i], *out_len);

    // Clear potentially sensitive information
    for(int j=0; j<sizeof(pkcs_block); j++) pkcs_block[j]=0;
    //memset((uint8_t *)pkcs_block, 0, sizeof(pkcs_block));

    return status;
}

int rsa_private_encrypt(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_sk_t *sk)
{
    int status;
    uint8_t pkcs_block[RSA_MAX_MODULUS_LEN];
    uint32_t i, modulus_len;

    modulus_len = (sk->bits + 7) / 8;
    if(in_len + 11 > modulus_len)
        return ERR_WRONG_LEN;

    pkcs_block[0] = 0;
    pkcs_block[1] = 1;
    for(i=2; i<modulus_len-in_len-1; i++) {
        pkcs_block[i] = 0xFF;
    }

    pkcs_block[i++] = 0;

    for(int j=0; j<in_len; j++) pkcs_block[i+j] = in[j];
    //memcpy((uint8_t *)&pkcs_block[i], (uint8_t *)in, in_len);

    status = private_block_operation(out, out_len, pkcs_block, modulus_len, sk);

    // Clear potentially sensitive information
    for(int j=0;j<sizeof(pkcs_block);j++) pkcs_block[j]=0;
    //memset((uint8_t *)pkcs_block, 0, sizeof(pkcs_block));

    return status;
}

int rsa_private_decrypt(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_sk_t *sk)
{
    int status;
    uint8_t pkcs_block[RSA_MAX_MODULUS_LEN];
    uint32_t i, modulus_len, pkcs_block_len;

    modulus_len = (sk->bits + 7) / 8;
    if(in_len > modulus_len)
        return ERR_WRONG_LEN;

    status = private_block_operation(pkcs_block, &pkcs_block_len, in, in_len, sk);
    if(status != 0)
        return status;

    if(pkcs_block_len != modulus_len)
        return ERR_WRONG_LEN;

    if((pkcs_block[0] != 0) || (pkcs_block[1] != 2))
        return ERR_WRONG_DATA;

    for(i=2; i<modulus_len-1; i++) {
        if(pkcs_block[i] == 0)  break;
    }

    i++;
    if(i >= modulus_len)
        return ERR_WRONG_DATA;
    *out_len = modulus_len - i;
    if(*out_len + 11 > modulus_len)
        return ERR_WRONG_DATA;
    
    for(int j=0;j<*out_len;j++) out[j]=pkcs_block[j+i];
    //memcpy((uint8_t *)out, (uint8_t *)&pkcs_block[i], *out_len);
    // Clear potentially sensitive information
    for(int j=0;j<sizeof(pkcs_block);j++) pkcs_block[j]=0;
    //memset((uint8_t *)pkcs_block, 0, sizeof(pkcs_block));

    return status;
}

static int public_block_operation(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_pk_t *pk)
{
    uint32_t edigits, ndigits;
    bn_t c[BN_MAX_DIGITS], e[BN_MAX_DIGITS], m[BN_MAX_DIGITS], n[BN_MAX_DIGITS];

    bn_decode(m, BN_MAX_DIGITS, in, in_len);
    bn_decode(n, BN_MAX_DIGITS, pk->modulus, RSA_MAX_MODULUS_LEN);
    bn_decode(e, BN_MAX_DIGITS, pk->exponent, RSA_MAX_MODULUS_LEN);

    ndigits = bn_digits(n, BN_MAX_DIGITS);
    edigits = bn_digits(e, BN_MAX_DIGITS);

    if(bn_cmp(m, n, ndigits) >= 0) {
        return ERR_WRONG_DATA;
    }

    bn_mod_exp(c, m, e, edigits, n, ndigits);

    *out_len = (pk->bits + 7) / 8;
    bn_encode(out, *out_len, c, ndigits);

    // Clear potentially sensitive information
    for(int i=0;i<sizeof(BN_MAX_DIGITS);i++)
    {
        c[i]=0; m[i]=0;
    }
    //memset((uint8_t *)c, 0, sizeof(c));
    //memset((uint8_t *)m, 0, sizeof(m));

    return 0;
}

static int private_block_operation(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_sk_t *sk)
{
    uint32_t cdigits, ndigits, pdigits;
    bn_t c[BN_MAX_DIGITS], cp[BN_MAX_DIGITS], cq[BN_MAX_DIGITS];
    bn_t dp[BN_MAX_DIGITS], dq[BN_MAX_DIGITS], mp[BN_MAX_DIGITS], mq[BN_MAX_DIGITS];
    bn_t n[BN_MAX_DIGITS], p[BN_MAX_DIGITS], q[BN_MAX_DIGITS], q_inv[BN_MAX_DIGITS], t[BN_MAX_DIGITS];

    bn_decode(c, BN_MAX_DIGITS, in, in_len);
    bn_decode(n, BN_MAX_DIGITS, sk->modulus, RSA_MAX_MODULUS_LEN);
    bn_decode(p, BN_MAX_DIGITS, sk->prime1, RSA_MAX_PRIME_LEN);
    bn_decode(q, BN_MAX_DIGITS, sk->prime2, RSA_MAX_PRIME_LEN);
    bn_decode(dp, BN_MAX_DIGITS, sk->prime_exponent1, RSA_MAX_PRIME_LEN);
    bn_decode(dq, BN_MAX_DIGITS, sk->prime_exponent2, RSA_MAX_PRIME_LEN);
    bn_decode(q_inv, BN_MAX_DIGITS, sk->coefficient, RSA_MAX_PRIME_LEN);

    cdigits = bn_digits(c, BN_MAX_DIGITS);
    ndigits = bn_digits(n, BN_MAX_DIGITS);
    pdigits = bn_digits(p, BN_MAX_DIGITS);

    if(bn_cmp(c, n, ndigits) >= 0)
        return ERR_WRONG_DATA;

    bn_mod(cp, c, cdigits, p, pdigits);
    bn_mod(cq, c, cdigits, q, pdigits);
    bn_mod_exp(mp, cp, dp, pdigits, p, pdigits);
    bn_assign_zero(mq, ndigits);
    bn_mod_exp(mq, cq, dq, pdigits, q, pdigits);

    if(bn_cmp(mp, mq, pdigits) >= 0) {
        bn_sub(t, mp, mq, pdigits);
    } else {
        bn_sub(t, mq, mp, pdigits);
        bn_sub(t, p, t, pdigits);
    }

    bn_mod_mul(t, t, q_inv, p, pdigits);
    bn_mul(t, t, q, pdigits);
    bn_add(t, t, mq, ndigits);

    *out_len = (sk->bits + 7) / 8;
    bn_encode(out, *out_len, t, ndigits);

    // Clear potentially sensitive information
    /*
    memset((uint8_t *)c, 0, sizeof(c));
    memset((uint8_t *)cp, 0, sizeof(cp));
    memset((uint8_t *)cq, 0, sizeof(cq));
    memset((uint8_t *)dp, 0, sizeof(dp));
    memset((uint8_t *)dq, 0, sizeof(dq));
    memset((uint8_t *)mp, 0, sizeof(mp));
    memset((uint8_t *)mq, 0, sizeof(mq));
    memset((uint8_t *)p, 0, sizeof(p));
    memset((uint8_t *)q, 0, sizeof(q));
    memset((uint8_t *)q_inv, 0, sizeof(q_inv));
    memset((uint8_t *)t, 0, sizeof(t));
    */
    return 0;
}

//end of rsa.cpp

//start of keys.h
#define KEY_M_BITS      2048

// KEY_2048
__constant uchar key_m[] = {
		0xb7, 0xe9, 0x74, 0x4b, 0x45, 0xfa, 0xa6, 0x20, 0xd3, 0x1c, 0x30, 0xe9, 0x63, 0x86, 0xe9, 0xcd,
		0x5f, 0xb9, 0x93, 0xde, 0xca, 0x45, 0xc9, 0xd6, 0x08, 0x94, 0xf7, 0x7d, 0xb9, 0xee, 0xa9, 0xd0,
		0x78, 0x45, 0x76, 0x94, 0x80, 0x9d, 0xf7, 0x05, 0x24, 0xd7, 0x30, 0xe2, 0xc0, 0x0f, 0x04, 0x6e,
		0x60, 0x53, 0x23, 0xbd, 0x50, 0x03, 0xbf, 0x2c, 0xa9, 0xbb, 0xb4, 0x5c, 0xc5, 0x11, 0x5a, 0x1d,
		0xce, 0x25, 0x7d, 0x42, 0x03, 0x4f, 0x7e, 0x1c, 0x7a, 0x3e, 0x1a, 0x68, 0xe8, 0x9a, 0x00, 0x10,
		0x8d, 0x18, 0x28, 0xac, 0x26, 0xbd, 0x71, 0xae, 0x4a, 0xc9, 0xb9, 0x23, 0x0b, 0x9b, 0xc1, 0x01,
		0x67, 0x46, 0xa9, 0x01, 0x5e, 0x70, 0xf1, 0xd9, 0xbd, 0x7f, 0x56, 0x4b, 0x97, 0x61, 0x64, 0xff,
		0xc1, 0xd9, 0x6e, 0x93, 0xab, 0x40, 0x66, 0xd5, 0xcb, 0xf4, 0x02, 0xf5, 0xfc, 0x53, 0x11, 0x51,
		0xa9, 0x80, 0x5c, 0x07, 0x16, 0xab, 0xcb, 0x98, 0x25, 0xfe, 0x02, 0xf3, 0x89, 0x7e, 0x57, 0x91,
		0x7a, 0x64, 0xcc, 0x2c, 0x7a, 0x71, 0xe8, 0x83, 0x33, 0x59, 0x0a, 0xa9, 0x59, 0x23, 0xcf, 0x4a,
		0x6b, 0xe4, 0x24, 0x1a, 0xf7, 0x8c, 0xa9, 0x04, 0x5d, 0x65, 0xb6, 0x74, 0x87, 0x19, 0x42, 0x49,
		0xe3, 0x69, 0x03, 0xdd, 0xa4, 0xc9, 0x75, 0xfe, 0xa7, 0x3c, 0x07, 0xc1, 0x91, 0x67, 0x54, 0x45,
		0xfe, 0x5f, 0xcf, 0x45, 0x72, 0xf8, 0xbd, 0x47, 0x95, 0xba, 0x81, 0xa7, 0x54, 0x50, 0x55, 0x29,
		0x92, 0x2f, 0x81, 0x82, 0x71, 0x9b, 0x43, 0x1c, 0xeb, 0x27, 0x16, 0xca, 0x87, 0xe2, 0xba, 0x83,
		0xa0, 0x1e, 0x85, 0xef, 0x75, 0xe4, 0x63, 0x88, 0x2d, 0x0b, 0x53, 0x76, 0xb6, 0xb3, 0xd6, 0x68,
		0x19, 0xe2, 0x6c, 0x2b, 0x67, 0x4f, 0x0a, 0x9d, 0xde, 0xfe, 0x93, 0x42, 0x43, 0xce, 0x87, 0xad};

__constant uchar key_e[] = {
		0x01, 0x00, 0x01}; //65537

//================================================hardcoded key===========================================//
__constant uchar key_puf[16] = {0x16, 0xa9, 0xfe, 0x80, 0x07, 0x02, 0xab, 0xcb,
					0x98, 0x25, 0x57, 0x5c, 0xf3, 0x7e, 0x91, 0x89};
//================================================hardcoded key===========================================//

//end of keys.h

void set_pk(rsa_pk_t *pk)
{
    pk->bits = KEY_M_BITS;
    for(int i=0; i<sizeof(key_m); i++) 
        pk->modulus[RSA_MAX_MODULUS_LEN-sizeof(key_m) + i] = key_m[i];
    for(int i=0; i<sizeof(key_e); i++)
        pk->exponent[RSA_MAX_MODULUS_LEN-sizeof(key_e) + i]=key_e[i];

}

void rsa_2048_key(uint8_t* key, uint8_t* out_data)
{
	rsa_pk_t pk = {0};
	uint32_t output_len;
	uint8_t key_len = (uint8_t)16;

	set_pk(&pk);
    //uint8_t key[16];
    //for(int i = 0; i < 16; i++) key[i]=key_puf[i];
	rsa_public_encrypt(out_data, &output_len, key, key_len, &pk);
    //for(int i = 0; i < output_len; i++) out_data[i] = out_buffer[i];

}

#define AESGCM_MAC_SIZE 16
#define AESGCM_IV_SIZE 12
#define AESGCM_TAG_SIZE 16
#define MAX_LEN 78000 

__constant uint8_t R1[128] = { 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, };

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

__constant static uint8_t SBox[256] = {

	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
	0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
	0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
	0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
	0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
	0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
	0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
	0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
	0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
	0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
	0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
	0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
	0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
	0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
	0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
	0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
	0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16

};

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
	int j = 0;
     __attribute__((opencl_unroll_hint(4)))
	for (j = 0; j < 4; j++) {
        col[0] = state[j];
        col[1] = state[4+j];
        col[2] = state[8+j];
        col[3] = state[12+j];

		Multi(a, col, res);

        state[j] = res[0];
        state[4+j] = res[1];
        state[8+j] = res[2];
        state[12+j] = res[3];
	}
}

void AddRoundKey(uint8_t *state, uint8_t *w, int r) {
     __attribute__((opencl_unroll_hint(4)))
	for (int c = 0; c < 4; c++) {
		state[4 * 0 + c] = state[4 * 0 + c] ^ w[16 * r + 4 * c + 0];
		state[4 * 1 + c] = state[4 * 1 + c] ^ w[16 * r + 4 * c + 1];
		state[4 * 2 + c] = state[4 * 2 + c] ^ w[16 * r + 4 * c + 2];
		state[4 * 3 + c] = state[4 * 3 + c] ^ w[16 * r + 4 * c + 3];
	}
}


void Sub(uint8_t *w) {
     __attribute__((opencl_unroll_hint(4)))
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


//uint8_t R[] = { 0x02, 0x00, 0x00, 0x00 };

uint8_t * Rcon(uint8_t* R, int i) {
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
     __attribute__((opencl_unroll_hint(4)))
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
			uint8_t R[4] = {0x02, 0x00, 0x00, 0x00}; 
			Add(tmp, Rcon(R, i / 4), tmp);

		}

		w[(4 * i) + 0] = w[4 * (i - 4) + 0] ^ tmp[0];
		w[(4 * i) + 1] = w[4 * (i - 4) + 1] ^ tmp[1];
		w[(4 * i) + 2] = w[4 * (i - 4) + 2] ^ tmp[2];
		w[(4 * i) + 3] = w[4 * (i - 4) + 3] ^ tmp[3];
	}
}

void Encrypt(uint8_t *PlainText, uint8_t *CipherText, uint8_t *w) {

	uint8_t state[4 * 4];
	int r, i;
    __attribute__((opencl_unroll_hint(4)))
	for (i = 0; i < 4; i++) {
			//state[4 * i + j] = PlainText[i + 4 * j];
        state[4*i] = PlainText[i];
        state[4*i + 1] = PlainText[i + 4];
        state[4*i + 2] = PlainText[i + 8];
        state[4*i + 3] = PlainText[i + 12];
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

    __attribute__((opencl_unroll_hint(4)))
	for (i = 0; i < 4; i++) {
		//for (j = 0; j < 4; j++) {
			//CipherText[i + 4 * j] = state[4 * i + j];
            CipherText[i] = state[4*i];
            CipherText[i + 4] = state[4*i + 1];
            CipherText[i + 8] = state[4*i + 2];
            CipherText[i + 12] = state[4*i + 3];
		//}
	}
}

void cpystr(uint8_t * X, uint8_t *Y, int len){
	int i;
    __attribute__((opencl_unroll_hint(16)))
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
	uint8_t temp[12];
	uint8_t tamp[4];
	unsigned int d = 0;
    __attribute__((opencl_unroll_hint(12)))
	for (i = 0; i < 12; i++){
		temp[i] = X[i];
	}
    __attribute__((opencl_unroll_hint(4)))
	for (i = 12; i < 16; i++){
		tamp[i - 12] = X[i];
	}
    
    d += tamp[0]*256*256*256;
    d += tamp[1]*256*256;
    d += tamp[2]*256;
    d += tamp[3];
    
	d++;
	d = d % 0x100000000;

	for (i = 0; i < 4; i++){
		tamp[3 - i] = d % 256;
		d /= 256;
	}
    __attribute__((opencl_unroll_hint(12)))
	for (i = 0; i < 12; i++){
		X[i] = temp[i];
	}
    __attribute__((opencl_unroll_hint(4)))
	for (i = 12; i < 16; i++){
		X[i] = tamp[i - 12];
	}
}
void GCTR(int length, uint8_t *m, uint8_t *Y, uint8_t *ICB, uint8_t *ekey, int fin){
	// hexlen , n , m ,Y (output) , ICB , ekey(AES key expansion) , fin : firstCTR 0 , lastCTR 1
	int i, j, k, nowlen;
	uint8_t x1[16] = { 0, }, y1[16] = { 0, };
	uint8_t CIPH[16] = { 0, };
	nowlen = length;
	int round = length / 16 + 1;
    __attribute__((opencl_unroll_hint(4)))
	for (i = 0; i < round; i++){
		//if (nowlen >= 16){
            __attribute__((opencl_unroll_hint(16)))
			for (k = 0; k < 16; k++){
				x1[k] = 0;
				y1[k] = 0;
			}
            __attribute__((opencl_unroll_hint(16)))
			for (j = 0; j < 16; j++){
				x1[j] = m[i * 16 + j];
			}
			if (fin == 0)
				inc32(ICB);  // ICB_temp -> ICB
			Encrypt(ICB, CIPH, ekey);
            __attribute__((opencl_unroll_hint(16)))
			for (k = 0; k < 16; k++){
				y1[k] = x1[k] ^ CIPH[k];
			}
			//printf("\n");
            __attribute__((opencl_unroll_hint(16)))
			for (k = 0; k < 16; k++){
				Y[i * 16 + k] = y1[k];
			}
			nowlen -= 16;

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
        __attribute__((opencl_unroll_hint(16)))
		for (j = 0; j < 16; j++){
			tamp[j] = X1[i * 16 + j];
		}
        __attribute__((opencl_unroll_hint(16)))
		for (j = 0; j < 16; j++){
			Y1[j] = tmpY[j] ^ tamp[j];
		}
		Encrypt(zero, H, ekey);
		Multiplication(Y1, H);
        __attribute__((opencl_unroll_hint(16)))
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
	uint8_t lenIV[8];
	uint8_t ivtmp[MAX_LEN] = {0};

	//printf("%d\n", strlen(iv));
	if (n == 12){
        __attribute__((opencl_unroll_hint(12)))
		for (i = 0; i < 12; i++)
			j[i] = iv[i];
        __attribute__((opencl_unroll_hint(3)))
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
		//ivtmp = (uint8_t*)malloc(sizeof(uint8_t)*((IVlen + s + 64 + 64) / 8) + 1);
		//memset(ivtmp, 0, (IVlen + s + 64 + 64) / 8 + 1);
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
	uint8_t tamp[MAX_LEN];
	//int len;
	int cBlen = C_size * 8, aBlen = A_size * 8;
	int max = 16, max2 = 16, i = 0, j = 0, k = 0, val;

	while (C_size > max){
		max += 16;
	}
	while ((A_size > max2) && (A_size != 0)){
		max2 += 16;
	}
	//tamp = (uint8_t*)malloc(sizeof(uint8_t)*(max + 3));
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

	return val;
}

//encryption
int aes_gcm_encryption(uint8_t* data, uint8_t* key, uint8_t* auth_msg, uint8_t* iv, size_t hexlen, uint8_t* cipher_text, uint8_t* tag)
{
	uint8_t X[MAX_LEN] = {0}; 
	uint8_t Y[MAX_LEN] = {0}; 
	uint8_t m[MAX_LEN] = {0}; //message
	uint8_t A[16] = {0}; //mac
	int len;
	uint8_t J0[16] = { 0, }, ICB[16] = { 0. };

	uint8_t IV[16] = {0};
	uint8_t ekey[4 * 44] = { 0, };
	//plain text
    __attribute__((opencl_unroll_hint(128)))
	for(int i=0;i<hexlen;i++)
	{
		m[i] = data[i];
		Y[i] = data[i];
	}
	//mac
    __attribute__((opencl_unroll_hint(16)))
	for(int i = 0; i < AESGCM_MAC_SIZE; i++)
	{
		A[i] = auth_msg[i];
		X[i] = auth_msg[i];
	}
	//iv
    __attribute__((opencl_unroll_hint(12)))
	for (int i = 0; i < AESGCM_IV_SIZE; i++)
	{
		IV[i] = iv[i];
	}
	//compute cipher text
	KeyExpansion(key, ekey);
	gerJ0(IV, J0, ekey, AESGCM_IV_SIZE);  
	cpystr(ICB, J0, 16);  
	GCTR(hexlen, m, Y, ICB, ekey, 0); 
    __attribute__((opencl_unroll_hint(128)))
	for(int i = 0; i < hexlen; i++)
	{
		cipher_text[i] = Y[i];
	}
	//generate tag
	len = padding(Y, A, hexlen, AESGCM_MAC_SIZE);
	GHASH(len, Y, X, ekey);
	GCTR(16, X, Y, J0, ekey, 1); 
    __attribute__((opencl_unroll_hint(16)))
	for(int i = 0; i < 16; i++)
	{
		tag[i] = Y[i];
	}
	return 0;
}

//decrypt
int aes_gcm_decryption(uint8_t *tmp_msg, uint8_t* key, uint8_t *auth_msg, uint8_t *iv, uint8_t *tag, size_t hexlen, uint8_t* plain_text)
{
	uint8_t X[MAX_LEN] = {0}; 
	uint8_t Y[MAX_LEN] = {0}; 
	uint8_t C1[MAX_LEN] = {0}; 
	uint8_t T1[AESGCM_TAG_SIZE+1] = {0}; 
	uint8_t P[MAX_LEN] = {0};
	int len;
	uint8_t J0[16] = { 0, }, ICB[16] = { 0. };
	uint8_t C[MAX_LEN] = {0};
	uint8_t A[AESGCM_MAC_SIZE] = {0};
	uint8_t IV[AESGCM_IV_SIZE] = {0};
	uint8_t T[AESGCM_TAG_SIZE] = {0};
	uint8_t ekey[4 * 44] = { 0, };

    __attribute__((opencl_unroll_hint(128)))
	for(int i = 0; i < hexlen; i++)
	{
		C[i] = tmp_msg[i];
	}
	//mac
    __attribute__((opencl_unroll_hint(16)))
	for (int i = 0; i < AESGCM_MAC_SIZE; i++)
	{
		A[i] = auth_msg[i];
	}
	//iv
    __attribute__((opencl_unroll_hint(12)))
	for( int i = 0; i < AESGCM_IV_SIZE; i++)
	{
		IV[i] = iv[i];
	}
	//tag
    __attribute__((opencl_unroll_hint(16)))
	for( int i = 0; i < AESGCM_TAG_SIZE; i++)
	{
		T[i] = tag[i];
	}

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
	//if (cmpArr(T,T1, AESGCM_TAG_SIZE))
	//{
		//success

        __attribute__((opencl_unroll_hint(128)))
		for(int i = 0; i < hexlen; i++)
		{
			plain_text[i] = P[i];
		}
	//}
	//else{
		//fail
	//	return -1;
	//}

	return 0;
}

int encryption(uint8_t* iv, uint8_t* auth_msg, uint8_t* data, int hexlen, uint8_t* key, uint8_t* output)
{
    uint8_t tag[16] = {0};
	uint8_t encrypted_msg[MAX_LEN];

	//int aes_gcm_encryption(uint8_t* data, __constant uint8_t* key, uint8_t* auth_msg, uint8_t* iv, size_t hexlen, uint8_t* cipher_text, uint8_t* tag)
	aes_gcm_encryption(data, key, auth_msg, iv, hexlen, encrypted_msg, tag);
	__attribute__((opencl_unroll_hint(12)))  //iv+mac+msg+tag
	for(int i = 0; i < 12; i++)
	{
		output[i] = iv[i];
	}
    __attribute__((opencl_unroll_hint(16)))
	for(int i = 0; i < 16; i++)
	{
		output[12+i] = auth_msg[i];
	}
    __attribute__((opencl_unroll_hint(128)))
	for(int i = 0; i < hexlen; i++)
	{
		output[28+i] = encrypted_msg[i];
	}
    __attribute__((opencl_unroll_hint(16)))
	for(int i = 0; i < 16; i++)
	{
		output[28 + hexlen + i] = tag[i];
	}
    return 0;

}

int decryption(uint8_t* data, int hexlen, uint8_t* key, uint8_t* plain_text)
{
    uint8_t encrypted_msg[MAX_LEN];
    uint8_t auth_msg[16];
    uint8_t iv[12];
    uint8_t tag[16];
    uint8_t plain_msg[MAX_LEN];

    //prepare variables
	__attribute__((opencl_unroll_hint(12)))   //iv + mac + msg + tag
    for(int i = 0; i < AESGCM_IV_SIZE; i++)
    {
        iv[i] = data[i];
    }
	__attribute__((opencl_unroll_hint(16)))
    for(int i = 0; i < AESGCM_MAC_SIZE; i++)
    {
        auth_msg[i] = data[AESGCM_IV_SIZE + i];
    }
	__attribute__((opencl_unroll_hint(128)))
    for(int i = 0; i < hexlen; i++)
    {
        encrypted_msg[i] = data[AESGCM_IV_SIZE + AESGCM_MAC_SIZE + i];
    }
	__attribute__((opencl_unroll_hint(16)))
    for(int i = 0; i < AESGCM_TAG_SIZE; i++)
    {
        tag[i] = data[AESGCM_IV_SIZE + AESGCM_MAC_SIZE + hexlen + i];
    }
    //decrypt

    int tmp_result = aes_gcm_decryption(encrypted_msg, key, auth_msg, iv, tag, hexlen, plain_msg);
    
    // if(tmp_result != 0)
    // {   //fail
    //     plain_text[0] = 0xff;
    //     plain_text[1] = 0xff;
    // }
    
    
    // else
    // {   //success
    
		__attribute__((opencl_unroll_hint(128)))
        for(int i = 0; i < hexlen; i++)
        {
            plain_text[i] = plain_msg[i];
        }
    //}
    return 0;
}


void int_to_uint8_t(uint8_t* key, int *buffer)
{
    __attribute__((opencl_unroll_hint(16)))
    for(int i = 0; i < 16; i++)
    {
        key[i] += buffer[0+8*i]<<7;
        key[i] += buffer[1+8*i]<<6;
        key[i] += buffer[2+8*i]<<5;
        key[i] += buffer[3+8*i]<<4;
        key[i] += buffer[4+8*i]<<3;
        key[i] += buffer[5+8*i]<<2;
        key[i] += buffer[6+8*i]<<1;
        key[i] += buffer[7+8*i];
    }
}
__constant uint8_t key_default[16] = {0xA8, 0xAF, 0x2D, 0x96, 0x43, 0x4F, 0x59, 0x29, 0x0C, 0xF8, 0x9A, 0x40, 0x01, 0xE4, 0x43, 0x57};

// pipe int p0 __attribute__((xcl_reqd_pipe_depth(32)));
pipe int p1 __attribute__((xcl_reqd_pipe_depth(32)));

pipe uint8_t p2 __attribute__((xcl_reqd_pipe_depth(32)));
pipe uint8_t p3 __attribute__((xcl_reqd_pipe_depth(32)));

kernel 
__attribute__ ((reqd_work_group_size(1, 1, 1)))
void krnl_input(__global int* challenge, int challenge_size)
{

    __attribute__((xcl_pipeline_loop)) 
    for(int i = 0; i < challenge_size; i++)
    {
        write_pipe_block(p1, &challenge[i]);
    }
}

kernel
__attribute__ ((reqd_work_group_size(1, 1, 1)))
void krnl_secure_monitor(__global uint8_t* input, int challenge_size, int input_size, int flag, __global uint8_t* output)
{
    int buffer[256];
    uchar key_tmp[16];
    uint8_t key[256];
    uint8_t buffer_in[660];
    uint8_t buffer_out[660];
    uint8_t response[16];

    __attribute__((xcl_pipeline_loop)) 
    for(int i = 0; i < challenge_size; i++)
    {
        read_pipe_block(p1, &buffer[i]);
    }
      
    if(flag == 0)  //generate response
    {
        for(int i = 0; i < 16; i++)
        {
            response[i] = (uint8_t)buffer[i];
            write_pipe_block(p2, &response[i]);
        }
    }
    else if(flag == 1) // generate key, and send it to the kernel
    {
        
        int_to_uint8_t(key_tmp, buffer);
        for(int i = 0 ; i < 16; i++)
        {
            key_tmp[i] = key_default[i];
        }
        rsa_2048_key(key_tmp, key);
        for(int i = 0; i < 256; i++)
        {
            output[i] = key[i];
            write_pipe_block(p2, &key[i]);
        }
    }
    
    else if(flag == 2) // encryption, and send the key + data to the kernel
    {
        //int hexlen;
        for(int i = 0 ;i < input_size; i++)
        {
            buffer_in[i] = input[i];
        }
        //int encryption(uint8_t* data, int hexlen, uint8_t* key, uint8_t* output)
        int_to_uint8_t(key_tmp, buffer);
        for(int i = 0 ; i < 16; i++)
        {
            key_tmp[i] = key_default[i];
        }
        int hexlen = input_size - 44;
        decryption(buffer_in, hexlen, key_tmp, buffer_out);
        //encryption(buffer_in, input_size, key_tmp, buffer_out);
        //int encrypted_size = input_size + 44;
        for(int i = 0; i < 16; i++)
        {
            buffer_out[hexlen+i] = input[hexlen + 28 + i];  //tag
            buffer_out[hexlen+i+16] = key_tmp[i];
            buffer_out[hexlen+i+44] = input[i + 12];
        }
        for(int i = 0 ; i < 12; i++)
        {
            buffer_out[hexlen+i+32] = input[i];
        }
        for(int i = 0; i < input_size; i++) 
        {   
            write_pipe_block(p2, &buffer_out[i]);
            //key_output[i] = buffer_out[i];
            output[i] = input[i];
        }

    }
    
    else if(flag == 3) //no encryption, send the data to the kernel
    {
        __attribute__((xcl_pipeline_loop))
        for(int i = 0; i < input_size; i++)
        {   
            //write_pipe_block(p2, &input[i]);
            output[i] = input[i];
        }        
    }
    
}

kernel
__attribute__ ((reqd_work_group_size(1, 1, 1)))
void krnl_dummy(__global uint8_t* buffer,int input_size)
{
    //uint8_t buffer;
    __attribute__((xcl_pipeline_loop))
    for(int i = 0; i < input_size; i++)
    {
        read_pipe_block(p2, &buffer[i]);
        write_pipe_block(p3, &buffer);
    }
}


kernel
__attribute__ ((reqd_work_group_size(1, 1, 1)))
void krnl_output(__global uint8_t* output, int output_size, int flag)
{
    uint8_t buffer_in[66000];
    uint8_t buffer_out[66000];
    uint8_t key[16];

    if(flag == 0)  //output response
    {
        for(int i = 0 ; i < 16; i++)
        {
            read_pipe_block(p3, &output[i]);
        }
    }   
    else if(flag == 1)
    {
        
        for(int i = 0; i < 256; i++)
        {
            read_pipe_block(p3, &buffer_in[i]);
        }
        for(int i = 0 ;i < 256; i++)
        {
            output[i] = buffer_in[i];
        }

    }
    
    else if(flag == 2)  //output encrypted message
    {
        //int hexlen = output_size - 44;
        //int receive_size = hexlen + 16;
        //read data
        uint8_t tag[16];
        uint8_t iv[12];
        uint8_t auth_msg[16];
        int receive_size = output_size + 16;
        int hexlen = output_size - 44;
        for(int i = 0; i < receive_size; i++)  
        {   
            read_pipe_block(p3, &buffer_in[i]);
        }

        for(int i = 0; i < 16; i++)
        {
            key[i] = buffer_in[receive_size - 44 + i];
            tag[i] = buffer_in[receive_size - 60 + i];
            auth_msg[i] = buffer_in[receive_size - 16 + i];
            //buffer_in[encrypted_size+i] = 0x00;
        }
        for(int i = 0 ; i < 12; i++)
        {
            iv[i] = buffer_in[receive_size - 28 + i];
        }
        //int decryption(uint8_t* data, int hexlen, uint8_t* key, uint8_t* plain_text)
        decryption(buffer_in, output_size, key, buffer_out);
        for(int i = 0 ; i < 16; i++)
        {
            key[i] = key_default[i];
        }
        encryption(iv, auth_msg, buffer_in, hexlen, key, buffer_out); 
        for(int i = 0 ; i<output_size - 16; i++)
        {
            output[i] = buffer_out[i];
        }
        for(int i = 0 ; i < 16; i++)
        {
            output[i + output_size - 16] = tag[i];
        }

    }
    
    else if(flag == 2) 
    {
        __attribute__((xcl_pipeline_loop))       
        for(int i = 0; i<output_size; i++)
        {
            read_pipe_block(p3, &output[i]);
            output[i] = buffer_in[i];
        }  
     
    }
    

}
