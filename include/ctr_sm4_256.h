#include <stdint.h>
#include "sm4_expand.h"
#include "sm4.h"
void ctr128_inc(unsigned char *counter);
void ctr128_inc_nstep(unsigned char *counter,int step);
void crypto_ctr128_setKey(const void *key,SM4_EXPAND_KEY *ks);

void crypto_ctr128_encrypt( const char *in,//the data in must be times of 16 bytes
							char *out,
							int len,
							const void *key,SM4_EXPAND_KEY *ks,
							unsigned char ivec[16],//only uses the lower 64 bit of ivec as counter
							unsigned char ecount_buf[16],
							unsigned int num,//(*num)
							int Cypher);//缺省值
