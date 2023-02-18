#include "ctr_sm4_256.h"
#include "string.h"
#include <omp.h>
#define ossl_inline inline
#define CTR_PARALLEL 6
static ossl_inline uint64_t load_64_be(const uint8_t*b,uint32_t n){//load n_th elements of 64 block in b array to become  a real uint64_t
	return ((uint64_t)b[8*n]<<56)|
		   ((uint64_t)b[8*n+1]<<48)|
		   ((uint64_t)b[8*n+2]<<40)|
		   ((uint64_t)b[8*n+3]<<32)|
		   ((uint64_t)b[8*n+4]<<24)|
		   ((uint64_t)b[8*n+5]<<16)|
		   ((uint64_t)b[8*n+6]<<8)|
		   ((uint64_t)b[8*n+7]);
	
	
	}
static ossl_inline void store_u64_be(uint64_t v,uint8_t *b){
	b[0] = (uint8_t)(v>>56);
	b[1] = (uint8_t)(v>>48);
	b[2] = (uint8_t)(v>>40);
	b[3] = (uint8_t)(v>>32);
	b[4] = (uint8_t)(v>>24);
	b[5] = (uint8_t)(v>>16);
	b[6] = (uint8_t)(v>>8);
	b[7] = (uint8_t)(v);
	}
static ossl_inline void store_u128_be(uint64_t v,uint8_t *b){


	//dump_hex(b,16);
	
	b[8] = (uint8_t)(v>>56);
	b[9] = (uint8_t)(v>>48);
	b[10] = (uint8_t)(v>>40);
	b[11] = (uint8_t)(v>>32);
	b[12] = (uint8_t)(v>>24);
	b[13] = (uint8_t)(v>>16);
	b[14] = (uint8_t)(v>>8);
	b[15] = (uint8_t)(v);
	}

void ctr128_inc(unsigned char *counter){//the counter should be endian
	
	uint64_t p;

	p = load_64_be(counter,1);
	
	
	
	p++;
	
	store_u128_be(p,counter);
	
	//dump_hex(counter,16);
	
	
	
	}
void ctr128_set_counter(unsigned char *counter,int set_num){
	uint64_t p;

	//p = load_64_be(counter,1);
	p=set_num;//just for testing, set it to zero everytime 
	store_u128_be(p,counter);
	
	}
void ctr128_inc_nstep(unsigned char *counter,int step){//the counter should be endian
	
	uint64_t p;

	p = load_64_be(counter,1);
	p+=step;
	
	store_u128_be(p,counter);
	
	//dump_hex(counter,16);
	
	
	
	}
	
	
void crypto_ctr128_setKey(const void *key,SM4_EXPAND_KEY *ks){
	ks = (SM4_EXPAND_KEY*)malloc(sizeof(SM4_EXPAND_KEY));
	sm4_expand_set_key(key,ks);
	
	}
	
void crypto_ctr128_encrypt(const char *in,char *out,
							int len,const void *key,SM4_EXPAND_KEY *ks,
							unsigned char ivec[16],unsigned char ecount_buf[16],
							unsigned int num,int Cypher){
	unsigned int n;
	#ifdef CTR_PARALLEL
    {
        omp_set_num_threads(CTR_PARALLEL);
        #pragma omp parallel
        {
            int parallell =CTR_PARALLEL;
        int omp_id = omp_get_thread_num();
        int length = len;
        length -= (16 * omp_id); // if detected the data block has allocated enough processors then it would get in the loop below
        unsigned char iv_p[16];
        unsigned char ecount_buf_p[32];
        uint8_t *out_t = out + omp_id * (16);
        const uint8_t *in_t = (in + omp_id * (16));

        int ind = 0;
        
        /* initialization of variables */
        for (int i = 0; i < 16; i++)
            iv_p[i] = ivec[16];
        ctr128_inc_nstep(iv_p, omp_id);
        while (length >= 16)
		{             
			sm4_expand_encrypt(iv_p, ecount_buf_p, ks);
			ctr128_inc_nstep(iv_p, parallell);
			for (ind = 0; ind < 16; ind++)
				out_t[ind] = in_t[ind] ^ ecount_buf_p[n];
			length -= 16 * parallell;
			out_t += 16 * parallell;
			in_t += 16 * parallell;
			ind = 0;
		}
                
            
        }
    }

    #else
    {  
		
		int l=0;
		n = num;
		while(len>=16){
					sm4_expand_encrypt(ivec,ecount_buf,ks);
					
					//dump_hex(ivec,16);
					ctr128_inc(ivec);
					
					//dump_hex(ecount_buf,16);
					for(n=0;n<16;n++)
						out[n] = in[n]^ecount_buf[n];
					//dump_hex(ecount_buf,32);
					len-=16;
					out+=16;
					in+=16;
					n=0;
				}	
				num = n;	
    }
    #endif
	
	
	return;
	}

