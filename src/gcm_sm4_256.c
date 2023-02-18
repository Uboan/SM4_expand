#include "gcm_sm4_256.h"
#include <string.h>
#include <omp.h>

#define ossl_inline inline
#define TABLE_BITS 4

#define PACK(s) ((size_t)(s) << (sizeof(size_t) * 8 - 16))
#define REDUCE1BIT(V)                                           \
    do                                                          \
    {                                                           \
        if (sizeof(size_t) == 8)                                \
        {                                                       \
            u64 T = U64(0xe100000000000000) & (0 - (V.lo & 1)); \
            V.lo = (V.hi << 63) | (V.lo >> 1);                  \
            V.hi = (V.hi >> 1) ^ T;                             \
        }                                                       \
        else                                                    \
        {                                                       \
            u32 T = 0xe1000000U & (0 - (u32)(V.lo & 1));        \
            V.lo = (V.hi << 63) | (V.lo >> 1);                  \
            V.hi = (V.hi >> 1) ^ ((u64)T << 32);                \
        }                                                       \
    } while (0)

static int WBCRYPTO_memcmp(const void *in_a, const void *in_b, size_t len)
{
    size_t i;
    const volatile unsigned char *a = in_a;
    const volatile unsigned char *b = in_b;
    unsigned char x = 0;

    for (i = 0; i < len; i++)
        x |= a[i] ^ b[i];

    return x;
}

/*-
 * Even though permitted values for TABLE_BITS are 8, 4 and 1, it should
 * never be set to 8. 8 is effectively reserved for testing purposes.
 * TABLE_BITS>1 are lookup-table-driven implementations referred to as
 * "Shoup's" in GCM specification. In other words OpenSSL does not cover
 * whole spectrum of possible table driven implementations. Why? In
 * non-"Shoup's" case memory access pattern is segmented in such manner,
 * that it's trivial to see that cache timing information can reveal
 * fair portion of intermediate hash value. Given that ciphertext is
 * always available to attacker, it's possible for him to attempt to
 * deduce secret parameter H and if successful, tamper with messages
 * [which is nothing but trivial in CTR mode]. In "Shoup's" case it's
 * not as trivial, but there is no reason to believe that it's resistant
 * to cache-timing attack. And the thing about "8-bit" implementation is
 * that it consumes 16 (sixteen) times more memory, 4KB per individual
 * key + 1KB shared. Well, on pros side it should be twice as fast as
 * "4-bit" version. And for gcc-generated x86[_64] code, "8-bit" version
 * was observed to run ~75% faster, closer to 100% for commercial
 * compilers... Yet "4-bit" procedure is preferred, because it's
 * believed to provide better security-performance balance and adequate
 * all-round performance. "All-round" refers to things like:
 *
 * - shorter setup time effectively improves overall timing for
 *   handling short messages;
 * - larger table allocation can become unbearable because of VM
 *   subsystem penalties (for example on Windows large enough free
 *   results in VM working set trimming, meaning that consequent
 *   malloc would immediately incur working set expansion);
 * - larger table has larger cache footprint, which can affect
 *   performance of other code paths (not necessarily even from same
 *   thread in Hyper-Threading world);
 *
 * Value of 1 is not appropriate for performance reasons.
 */

static void gcm_init_4bit(u128 Htable[16], u64 H[2])
{
    u128 V;

    Htable[0].hi = 0;
    Htable[0].lo = 0;
    V.hi = H[0];
    V.lo = H[1];

    Htable[8] = V;
    REDUCE1BIT(V);
    Htable[4] = V;
    REDUCE1BIT(V);
    Htable[2] = V;
    REDUCE1BIT(V);
    Htable[1] = V;
    Htable[3].hi = V.hi ^ Htable[2].hi, Htable[3].lo = V.lo ^ Htable[2].lo;
    V = Htable[4];
    Htable[5].hi = V.hi ^ Htable[1].hi, Htable[5].lo = V.lo ^ Htable[1].lo;
    Htable[6].hi = V.hi ^ Htable[2].hi, Htable[6].lo = V.lo ^ Htable[2].lo;
    Htable[7].hi = V.hi ^ Htable[3].hi, Htable[7].lo = V.lo ^ Htable[3].lo;
    V = Htable[8];
    Htable[9].hi = V.hi ^ Htable[1].hi, Htable[9].lo = V.lo ^ Htable[1].lo;
    Htable[10].hi = V.hi ^ Htable[2].hi, Htable[10].lo = V.lo ^ Htable[2].lo;
    Htable[11].hi = V.hi ^ Htable[3].hi, Htable[11].lo = V.lo ^ Htable[3].lo;
    Htable[12].hi = V.hi ^ Htable[4].hi, Htable[12].lo = V.lo ^ Htable[4].lo;
    Htable[13].hi = V.hi ^ Htable[5].hi, Htable[13].lo = V.lo ^ Htable[5].lo;
    Htable[14].hi = V.hi ^ Htable[6].hi, Htable[14].lo = V.lo ^ Htable[6].lo;
    Htable[15].hi = V.hi ^ Htable[7].hi, Htable[15].lo = V.lo ^ Htable[7].lo;
}
static const size_t rem_4bit[16] = {
    PACK(0x0000), PACK(0x1C20), PACK(0x3840), PACK(0x2460),
    PACK(0x7080), PACK(0x6CA0), PACK(0x48C0), PACK(0x54E0),
    PACK(0xE100), PACK(0xFD20), PACK(0xD940), PACK(0xC560),
    PACK(0x9180), PACK(0x8DA0), PACK(0xA9C0), PACK(0xB5E0)};

static void gcm_gmult_4bit(u64 Xi[2], const u128 Htable[16])
{
    u128 Z;
    int cnt = 15;
    size_t rem, nlo, nhi;
    const union
    {
        long one;
        char little;
    } is_endian = {1};
    nlo = ((const u8 *)Xi)[15]; 
    nhi = nlo >> 4; 
    nlo &= 0xf; 
    Z.hi = Htable[nlo].hi;
    Z.lo = Htable[nlo].lo;

    while (1)
    {
        rem = (size_t)Z.lo & 0xf;//后4位
        Z.lo = (Z.hi << 60) | (Z.lo >> 4);
        Z.hi = (Z.hi >> 4);
        if (sizeof(size_t) == 8)
            Z.hi ^= rem_4bit[rem];
        else
            Z.hi ^= (u64)rem_4bit[rem] << 32;

        Z.hi ^= Htable[nhi].hi;
        Z.lo ^= Htable[nhi].lo;

        if (--cnt < 0)
            break;

        nlo = ((const u8 *)Xi)[cnt];
        nhi = nlo >> 4;
        nlo &= 0xf;

        rem = (size_t)Z.lo & 0xf;
        Z.lo = (Z.hi << 60) | (Z.lo >> 4);
        Z.hi = (Z.hi >> 4);
        if (sizeof(size_t) == 8)
            Z.hi ^= rem_4bit[rem];
        else
            Z.hi ^= (u64)rem_4bit[rem] << 32;

        Z.hi ^= Htable[nlo].hi;
        Z.lo ^= Htable[nlo].lo;
    }

    if (is_endian.little)
    {
        u8 *p = (u8 *)Xi;
        u32 v;
        v = (u32)(Z.hi >> 32);
        PUTU32(p, v);
        v = (u32)(Z.hi);
        PUTU32(p + 4, v);
        v = (u32)(Z.lo >> 32);
        PUTU32(p + 8, v);
        v = (u32)(Z.lo);
        PUTU32(p + 12, v);
    }
    else
    {
        Xi[0] = Z.hi;
        Xi[1] = Z.lo;
    }
}

static void gcm_ghash_4bit(u64 Xi[2], const u128 Htable[16],
                           const u8 *inp, size_t len)
{
    u128 Z;
    int cnt;
    size_t rem, nlo, nhi;
    const union
    {
        long one;
        char little;
    } is_endian = {1};

    do
    {
        cnt = 15;
        nlo = ((const u8 *)Xi)[15];
        nlo ^= inp[15];
        nhi = nlo >> 4;
        nlo &= 0xf;

        Z.hi = Htable[nlo].hi;
        Z.lo = Htable[nlo].lo;

        while (1)
        {
            rem = (size_t)Z.lo & 0xf;
            Z.lo = (Z.hi << 60) | (Z.lo >> 4);
            Z.hi = (Z.hi >> 4);
            if (sizeof(size_t) == 8)
                Z.hi ^= rem_4bit[rem];
            else
                Z.hi ^= (u64)rem_4bit[rem] << 32;

            Z.hi ^= Htable[nhi].hi;
            Z.lo ^= Htable[nhi].lo;

            if (--cnt < 0)
                break;

            nlo = ((const u8 *)Xi)[cnt];
            nlo ^= inp[cnt];
            nhi = nlo >> 4;
            nlo &= 0xf;

            rem = (size_t)Z.lo & 0xf;
            Z.lo = (Z.hi << 60) | (Z.lo >> 4);
            Z.hi = (Z.hi >> 4);
            if (sizeof(size_t) == 8)
                Z.hi ^= rem_4bit[rem];
            else
                Z.hi ^= (u64)rem_4bit[rem] << 32;

            Z.hi ^= Htable[nlo].hi;
            Z.lo ^= Htable[nlo].lo;
        }

        if (is_endian.little)
        {

            u8 *p = (u8 *)Xi;
            u32 v;
            v = (u32)(Z.hi >> 32);
            PUTU32(p, v);
            v = (u32)(Z.hi);
            PUTU32(p + 4, v);
            v = (u32)(Z.lo >> 32);
            PUTU32(p + 8, v);
            v = (u32)(Z.lo);
            PUTU32(p + 12, v);
        }
        else
        {
            Xi[0] = Z.hi;
            Xi[1] = Z.lo;
        }
    } while (inp += 16, len -= 16);
}

#define MEMSET(B) memset(ctx->B.u, 0, sizeof(ctx->B.u));

void gcm_memset(GCM128_CONTEXT *ctx)
{
    ctx->ares = 0;
    ctx->mres = 0;
    ctx->ks = (SM4_EXPAND_KEY *)malloc(sizeof(SM4_EXPAND_KEY));
    MEMSET(Yi);
    MEMSET(Xi);
    MEMSET(EK0);
    MEMSET(EKi); // Yi, EKi, EK0, len, Xi, H;
    MEMSET(len);
    MEMSET(H);
#if TABLE_BITS == 8
    for (int i = 0; i < 256; i++)
    {
        ctx->Htable[i].hi = 0;
        ctx->Htable[i].lo = 0;
    }
#else
    for (int i = 0; i < 16; i++)
    {
        ctx->Htable[i].hi = 0;
        ctx->Htable[i].lo = 0;
    }

#endif
}

void gcm128_init(GCM128_CONTEXT *ctx, void *key) // generate round keys and lookup_tables
{
    const union
    {
        long one;
        char little;
    } is_endian = {1};

    gcm_memset(ctx); //初始化
    ctx->key = key; //Mainkey -- 128bit

    sm4_expand_set_key(key, ctx->ks); //get roundkey 
    sm4_expand_encrypt(ctx->H.c, ctx->H.c, ctx->ks); //generate hash mainkey for GHASH_H

    if (is_endian.little)
    {
        /* H is stored in host byte order */
#ifdef BSWAP8
        ctx->H.u[0] = BSWAP8(ctx->H.u[0]);
        ctx->H.u[1] = BSWAP8(ctx->H.u[1]);
#else
        u8 *p = ctx->H.c; //起始位置
        u64 hi, lo; //计算机无法直接表示128bit数据，因此用2个64bit变量的结构表示
        hi = (u64)GETU32(p) << 32 | GETU32(p + 4);      // p[0~7]
        lo = (u64)GETU32(p + 8) << 32 | GETU32(p + 12); // p[8~15]
        ctx->H.u[0] = hi;
        ctx->H.u[1] = lo;
#endif
    }

#if TABLE_BITS == 4
    gcm_init_4bit(ctx->Htable, ctx->H.u);//from hash mainkey generate 16 hash subkey
#endif
}

void gcm128_setiv(GCM128_CONTEXT *ctx, const unsigned char *iv, size_t len)
{
    const union
    {
        long one;
        char little;
    } is_endian = {1};
    unsigned int ctr;

    ctx->Yi.u[0] = 0; /* IV */
    ctx->Yi.u[1] = 0;
    ctx->Xi.u[0] = 0;
    ctx->Xi.u[1] = 0;
    ctx->len.u[0] = 0; /* AAD length */
    ctx->len.u[1] = 0; /* message length */
    ctx->ares = 0;
    ctx->mres = 0;

    if (len == 12)
    {
        memcpy(ctx->Yi.c, iv, 12); // Yi.c stores iv
        ctx->Yi.c[15] = 1;
        ctr = 1;
    }
    else
    {
        size_t i;
        u64 len0 = len;

        while (len >= 16)
        { // dealing with multiples of 16
            for (i = 0; i < 16; ++i)
                ctx->Yi.c[i] ^= iv[i]; // why ^?
            // GCM_MUL(ctx, Yi);
            gcm_gmult_4bit(ctx->Yi.u, ctx->Htable);
            // # define GCM_MUL(ctx,Xi)        (*gcm_gmult_p)(ctx->Xi.u,ctx->Htable)
            // # define GHASH(ctx,in,len)     (*gcm_ghash_p)(ctx->Xi.u,ctx->Htable,in,len)
            iv += 16;
            len -= 16;
        }
        if (len)
        {
            for (i = 0; i < len; ++i)
                ctx->Yi.c[i] ^= iv[i];
            gcm_gmult_4bit(ctx->Yi.u, ctx->Htable);
        }
        len0 <<= 3;
        if (is_endian.little)
        {
#ifdef BSWAP8
            ctx->Yi.u[1] ^= BSWAP8(len0);
#else // copy len0 to Yi.c
            ctx->Yi.c[8] ^= (u8)(len0 >> 56);
            ctx->Yi.c[9] ^= (u8)(len0 >> 48);
            ctx->Yi.c[10] ^= (u8)(len0 >> 40);
            ctx->Yi.c[11] ^= (u8)(len0 >> 32);
            ctx->Yi.c[12] ^= (u8)(len0 >> 24);
            ctx->Yi.c[13] ^= (u8)(len0 >> 16);
            ctx->Yi.c[14] ^= (u8)(len0 >> 8);
            ctx->Yi.c[15] ^= (u8)(len0);
#endif
        }
        else
            ctx->Yi.u[1] ^= len0;

        gcm_gmult_4bit(ctx->Yi.u, ctx->Htable);

        if (is_endian.little)
#ifdef BSWAP4
            ctr = BSWAP4(ctx->Yi.d[3]);
#else
            ctr = GETU32(ctx->Yi.c + 12);
#endif
        else
            ctr = ctx->Yi.d[3];
    }
    sm4_expand_encrypt(ctx->Yi.c, ctx->EK0.c, ctx->ks);
    ++ctr;
    if (is_endian.little)
#ifdef BSWAP4
        ctx->Yi.d[3] = BSWAP4(ctr);
#else
        PUTU32(ctx->Yi.c + 12, ctr); // ctr-->ctx->Yi.c
#endif
    else
        ctx->Yi.d[3] = ctr;
}

int gcm128_aad(GCM128_CONTEXT *ctx, const unsigned char *aad,
               size_t len)
{
    size_t i;
    unsigned int n;
    u64 alen = ctx->len.u[0]; // add length,  ctx->len.u[0] = 0
    //u64 := unsigned long long 
    if (ctx->len.u[1]) // length of message == 0
        return -2;
    alen += len; //alen = ctx->len.u[0] + len 
    if (alen > (U64(1) << 61) || (sizeof(len) == 8 && alen < len)) // larger than anything
        return -1;
    ctx->len.u[0] = alen; //alen = len = 20
    n = ctx->ares; 
    if (n) 
    { // last block of the add
        while (n && len){
            ctx->Xi.c[n] ^= *(aad++);
            --len;
            n = (n + 1) % 16; //???
        }
        if (n == 0)
            gcm_gmult_4bit(ctx->Xi.u, ctx->Htable);
        else{
            ctx->ares = n;
            return 0;
        }
    }
#ifdef GHASH
    if ((i = (len & (size_t)-16)))
    {
        GHASH(ctx, aad, i);
        aad += i;
        len -= i;
    }
#else
    while (len >= 16) {
        for (i = 0; i < 16; ++i) //aad = A(外边定义的)
            ctx->Xi.c[i] ^= aad[i]; // Xi.c stores add
        gcm_gmult_4bit(ctx->Xi.u, ctx->Htable);//
        aad += 16;
        len -= 16;
    }
#endif
    if (len){
        n = (unsigned int)len; // where n changed
        for (i = 0; i < len; ++i)
            ctx->Xi.c[i] ^= aad[i];
    }
    ctx->ares = n;
    return 0;
}


int gcm128_encrypt(GCM128_CONTEXT *ctx,
                   const unsigned char *in, unsigned char *out,
                   size_t len)
{
    const union
    {
        long one;
        char little;
    } is_endian = {1};
    unsigned int n, ctr;
    size_t i;
    u64 mlen = ctx->len.u[1]; // message length
    void *key = ctx->key;

    mlen += len;
    if (mlen > ((U64(1) << 36) - 32) || (sizeof(len) == 8 && mlen < len)) // surpass the size
        return -1;
    ctx->len.u[1] = mlen;

    if (ctx->ares)
    {
        gcm_gmult_4bit(ctx->Xi.u, ctx->Htable);
        ctx->ares = 0;
    }

    if (is_endian.little)
#ifdef BSWAP4
        ctr = BSWAP4(ctx->Yi.d[3]);
#else
        ctr = GETU32(ctx->Yi.c + 12); // the last 4 bytes are ctr
#endif
    else
        ctr = ctx->Yi.d[3];

    n = ctx->mres;
#if !defined(OPENSSL_SMALL_FOOTPRINT)
    if (16 % sizeof(size_t) == 0)
    { /* always true actually */
        do
        {
            if (n)
            { // I think this one is the padding process. and process the last block
                while (n && len)
                {                                                       // len==0, end
                    ctx->Xi.c[n] ^= *(out++) = *(in++) ^ ctx->EKi.c[n]; //= Eki.c^(in)
                    --len;
                    n = (n + 1) % 16;
                }
                if (n == 0) // everytime finishing encrypting 1 block, Xi*H
                    gcm_gmult_4bit(ctx->Xi.u, ctx->Htable);
                else
                { // if it is the end
                    ctx->mres = n;
                    return 0;
                }
            }

            while (len >= 16)
            {
                size_t *out_t = (size_t *)out;
                const size_t *in_t = (const size_t *)in;
                sm4_expand_encrypt(ctx->Yi.c, ctx->EKi.c, ctx->ks);

                ++ctr;
                if (is_endian.little)
                    PUTU32(ctx->Yi.c + 12, ctr);
                else
                    ctx->Yi.d[3] = ctr;
                for (i = 0; i < 16 / sizeof(size_t); ++i)
                    ctx->Xi.t[i] ^= out_t[i] = in_t[i] ^ ctx->EKi.t[i]; // Xi saves the cyphertext

                gcm_gmult_4bit(ctx->Xi.u, ctx->Htable); // multiply of H and Y
                // GCM_MUL(ctx, Xi);//starting GHASH
                out += 16;
                in += 16;
                len -= 16; // end GHASH
            }
            int q = 0;
            while (len)
            {
                out[q] = in[q];
                q++;
                len--;
            }
            ctx->mres = n;
            return 0;
        } while (0);
    }
#endif // SMALL_FOOTPRINT
    /*  for (i = 0; i < len; ++i) {
          if (n == 0) {
              crypto_encrypt(ctx->Yi.c,ctx->EKi.c,ctx->ks,ctx->block);
              //(*block) (ctx->Yi.c, ctx->EKi.c, key);
              ++ctr;
              if (is_endian.little)
  #ifdef BSWAP4
                  ctx->Yi.d[3] = BSWAP4(ctr);
  #else
                  PUTU32(ctx->Yi.c + 12, ctr);
  #endif
              else
                  ctx->Yi.d[3] = ctr;
          }
          ctx->Xi.c[n] ^= out[i] = in[i] ^ ctx->EKi.c[n];
          n = (n + 1) % 16;
          if (n == 0)
              GCM_MUL(ctx, Xi);
      }

      ctx->mres = n;
      return 0;*/
}

int gcm128_decrypt(GCM128_CONTEXT *ctx,
                   const unsigned char *in, unsigned char *out,
                   size_t len)
{
    const union
    {
        long one;
        char little;
    } is_endian = {1};
    unsigned int n, ctr;
    size_t i;
    u64 mlen = ctx->len.u[1];
    void *key = ctx->key;

    mlen += len;
    if (mlen > ((U64(1) << 36) - 32) || (sizeof(len) == 8 && mlen < len))
        return -1;
    ctx->len.u[1] = mlen;

    if (ctx->ares)
    {
        gcm_gmult_4bit(ctx->Xi.u, ctx->Htable);
        ctx->ares = 0;
    }

    if (is_endian.little)
#ifdef BSWAP4
        ctr = BSWAP4(ctx->Yi.d[3]);
#else
        ctr = GETU32(ctx->Yi.c + 12);
#endif
    else
        ctr = ctx->Yi.d[3];

    n = ctx->mres;
#if !defined(OPENSSL_SMALL_FOOTPRINT)
    if (16 % sizeof(size_t) == 0)
    { /* always true actually */
        do
        {
            if (n)
            {
                while (n && len)
                {
                    u8 c = *(in++);
                    *(out++) = c ^ ctx->EKi.c[n];
                    ctx->Xi.c[n] ^= c;
                    --len;
                    n = (n + 1) % 16;
                }
                if (n == 0)
                    gcm_gmult_4bit(ctx->Xi.u, ctx->Htable);
                else
                {
                    ctx->mres = n;
                    return 0;
                }
            }

            while (len >= 16)
            {
                size_t *out_t = (size_t *)out;
                const size_t *in_t = (const size_t *)in;
                sm4_expand_encrypt(ctx->Yi.c, ctx->EKi.c, ctx->ks);
                ++ctr;

                if (is_endian.little)
#ifdef BSWAP4
                    ctx->Yi.d[3] = BSWAP4(ctr);
#else
                    PUTU32(ctx->Yi.c + 12, ctr);
#endif
                else
                    ctx->Yi.d[3] = ctr;
                for (i = 0; i < 16 / sizeof(size_t); ++i)
                { // the only differences bewteen encryption and decryption
                    size_t c = in_t[i];
                    out_t[i] = in_t[i] ^ ctx->EKi.t[i];
                    ctx->Xi.t[i] ^= c;
                }
                gcm_gmult_4bit(ctx->Xi.u, ctx->Htable);
                out += 16;
                in += 16;
                len -= 16;
            }

            int q = 0;
            while (len)
            {
                out[q] = in[q];
                len--;
                q++;
            }

            ctx->mres = n;
            return 0;
        } while (0);
    }
#endif
}

int gcm128_finish(GCM128_CONTEXT *ctx, const unsigned char *tag,
                  size_t len)
{
    const union
    {
        long one;
        char little;
    } is_endian = {1};
    u64 alen = ctx->len.u[0] << 3;
    u64 clen = ctx->len.u[1] << 3;

    if (ctx->mres || ctx->ares)
        gcm_gmult_4bit(ctx->Xi.u, ctx->Htable);

    if (is_endian.little)
    {
#ifdef BSWAP8
        alen = BSWAP8(alen);
        clen = BSWAP8(clen);
#else
        u8 *p = ctx->len.c;

        ctx->len.u[0] = alen;
        ctx->len.u[1] = clen;

        alen = (u64)GETU32(p) << 32 | GETU32(p + 4);
        clen = (u64)GETU32(p + 8) << 32 | GETU32(p + 12);
#endif
    }

    ctx->Xi.u[0] ^= alen;
    ctx->Xi.u[1] ^= clen;
    gcm_gmult_4bit(ctx->Xi.u, ctx->Htable);

    ctx->Xi.u[0] ^= ctx->EK0.u[0];
    ctx->Xi.u[1] ^= ctx->EK0.u[1];

    if (tag && len <= sizeof(ctx->Xi))
        return WBCRYPTO_memcmp(ctx->Xi.c, tag, len);
    else
        return -1;
}

void gcm128_tag(GCM128_CONTEXT *ctx, unsigned char *tag, size_t len)
{
    gcm128_finish(ctx, NULL, 0);
    memcpy(tag, ctx->Xi.c,
           len <= sizeof(ctx->Xi.c) ? len : sizeof(ctx->Xi.c));
}
/*
GCM128_CONTEXT *gcm128_new(void *key, int block)
{
    GCM128_CONTEXT *ret;

    if ((ret = OPENSSL_malloc(sizeof(*ret))) != NULL)
        gcm128_init(ret, key, block);

    return ret;
}
*/
