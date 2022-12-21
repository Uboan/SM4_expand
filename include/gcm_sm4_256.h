#include <stdint.h>
#include <stdio.h>
#include "sm4_expand.h"
//codes from modes.h

#if (defined(_WIN32) || defined(_WIN64)) && !defined(__MINGW32__)
typedef __int64 i64;
typedef unsigned __int64 u64;
# define U64(C) C##UI64
#elif defined(__arch64__)
typedef long i64;
typedef unsigned long u64;
# define U64(C) C##UL
#else
typedef long long i64;
typedef unsigned long long u64;
# define U64(C) C##ULL
#endif

# define GCM_PARALLEL 4 //multi-process gcm 


# define GETU32(p)       ((u32)(p)[0]<<24|(u32)(p)[1]<<16|(u32)(p)[2]<<8|(u32)(p)[3])
# define PUTU32(p,v)     ((p)[0]=(u8)((v)>>24),(p)[1]=(u8)((v)>>16),(p)[2]=(u8)((v)>>8),(p)[3]=(u8)(v))

typedef unsigned int u32;
typedef unsigned char u8;
typedef struct gcm128_context GCM128_CONTEXT;

/*- GCM definitions */ typedef struct {
    u64 hi, lo;
} u128;

//end from modes.h

#define TABLE_BITS 4

GCM128_CONTEXT *gcm128_new(void *key);
void gcm128_init(GCM128_CONTEXT *ctx, void *key);
void gcm128_setiv(GCM128_CONTEXT *ctx, const unsigned char *iv,
                           size_t len);
int gcm128_aad(GCM128_CONTEXT *ctx, const unsigned char *aad,
                        size_t len);
int gcm128_encrypt(GCM128_CONTEXT *ctx,
                            const unsigned char *in, unsigned char *out,
                            size_t len);
int gcm128_decrypt(GCM128_CONTEXT *ctx,
                            const unsigned char *in, unsigned char *out,
                            size_t len);
/*int gcm typedef struct gcm128_context GCM128_CONTEXT;128_encrypt_ctr32(GCM128_CONTEXT *ctx,
                                  const unsigned char *in, unsigned char *out,
                                  size_t len, WBCRYPTO_ctr128_f stream);
int gcm128_decrypt_ctr32(GCM128_CONTEXT *ctx,
                                  const unsigned char *in, unsigned char *out,
                                  size_t len, WBCRYPTO_ctr128_f stream);
								   */
int gcm128_finish(GCM128_CONTEXT *ctx, const unsigned char *tag,
                           size_t len);
void gcm128_tag(GCM128_CONTEXT *ctx, unsigned char *tag, size_t len);
//void gcm128_release(GCM128_CONTEXT *ctx);



struct gcm128_context {
    /* Following 6 names follow names in GCM specification */
    union {
        u64 u[2];
        u32 d[4];
        u8 c[16];//original 16
        size_t t[16 / sizeof(size_t)];
    } Yi, EKi, EK0, len, Xi, H;
    /*
    * Relative position of Xi, H and pre-computed Htable is used in some
    * assembler modules, i.e. don't change the order!
    * H stands for Host,
    */
#if TABLE_BITS==8
    u128 Htable[256];
#else
    u128 Htable[16];
   
#endif
    unsigned int mres, ares;
    
    void *key;
	SM4_EXPAND_KEY *ks;
};

