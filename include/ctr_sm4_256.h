
#include <stdint.h>
#include "sm4.h"
void ctr128_inc(unsigned char *counter);
void ctr128_inc_nstep(unsigned char *counter,int step);
void crypto_ctr128_setKey(const void *key,SM4_KEY *ks);

void crypto_ctr128_encrypt( const char *in,//the data in must be times of 16 bytes
							char *out,//if it is Lai-Massey scheme, make sure out is twice larger than in
							int len,
							const void *key,SM4_KEY *ks,
							unsigned char ivec[16],//only uses the lower 64 bit of ivec as counter
							unsigned char ecount_buf[32],//the reason for ecount_buf being 32bytes is that the LM needs double output data space(*ecount_buf)
							unsigned int num,//(*num)
							int Cypher);
//some parameters need to be justified