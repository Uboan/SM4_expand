#include<sm4_256_LM_cbc.h>

void sm4_256_LM_cbc_set_key(const uint8_t *key2,SM4_KEY *ks){
    sm4_256_set_key_lai_massey(key2,ks);
}

void sm4_256_LM_cbc_encrypt(uint8_t *in,uint8_t *out,uint8_t *ivec,size_t len,uint8_t *key1,SM4_KEY *ks){
    
    size_t n; 
    uint8_t * out1 = out;
    unsigned char plbufLeft[16];//输入缓存左
    unsigned char ivbuf[16];//异或变量缓存
    unsigned char clbufLeft[16];//输出缓存左
    unsigned char clbufRight[16];//输出缓存右
    uint8_t * in1 = in;
    // printf("\n输入明文：");
    // dump_hex(in1, len);
    for (size_t i = 0; i < 16; i++)
    {   //装填初始变量
        ivbuf[i] = ivec[i]; 
    }

    int i = 0;
    while(len >= 16)//分组长度为16byte
    {
        for(n = 0; n < 16; ++n)
        {
            plbufLeft[n] = in1[n] ^ ivbuf[n];//缓存:明文与初始变量进行异或
           //key everytime
            
        }
        // printf("\n明文异或：");
        // dump_hex(plbufLeft, 16);
        sm4_256_encrypt_lai_massey(plbufLeft,key1,clbufLeft,clbufRight,ks);
        // printf("\n密文：");
        // dump_hex(clbufLeft, 16);
        // printf("\nR8：");
        // dump_hex(clbufRight, 16);
        for(n = 0; n < 16; ++n)
        {
            out1[n] = clbufLeft[n]; 
            out1[n+16] = clbufRight[n];
        }
        // printf("\n密文+r8：");
        // dump_hex(out1, 32);
        //一轮完成.........
        for (size_t i = 0; i < 16; i++)
        {
            ivbuf[i] = clbufLeft[i]; 
        }
        
        // printf("\n加密iv:");
        // dump_hex(iv, 16);
        len -= 16;
        in1 += 16;
        out1 += 32;
    }
    
    if (len > 0){//不足16byte的数据在这里处理，有补全函数可以在这补全
        for (n = 0; n < len; n++)
        {
           out1[n] = in1[n];
        }
        
    }
    //  printf("\nresult:");
    //  dump_hex(out, 65);
    
}

void sm4_256_LM_cbc_decrypt(uint8_t *in,uint8_t *out,uint8_t *ivec,size_t len,SM4_KEY *ks){
    
    size_t n; 
    uint8_t * out1 = out;
    unsigned char plbufLeft[16];//输入缓存左
    unsigned char plbufRight[16];//输入缓存右
    unsigned char clbufLeft[16];//输出缓存左
    unsigned char clbufRight[16];//输出缓存右
    unsigned char ivbuf[16];//异或变量缓存
    uint8_t * in1 = in;
    int i = 0;
    // printf("\n密文：");
    // dump_hex(in1, 65);
    for (size_t i = 0; i < 16; i++)
        {   //装填初始变量
            ivbuf[i] = ivec[i]; 
        }

    while(len >= 16)//分组长度为16byte
    {
        for(n = 0; n < 16; ++n)
        {
           plbufLeft[n] = in1[n];
           plbufRight[n] = in1[n+16];//把输入中的密文部分和R8分开
            
        }
        // printf("\n输入密文：");
        // dump_hex(plbufLeft, 16);
        // printf("\nr8:");
        // dump_hex(plbufRight,16);
        sm4_256_decrypt_lai_massey(plbufLeft,plbufRight,clbufLeft,clbufRight,ks);
        // printf("\nkey1:");
        // dump_hex(clbufRight,16);
        // printf("\n明文异或后的值:");
        // dump_hex(clbufLeft,16);
        //  printf("\n异或变量:");
        // dump_hex(iv,16);
        for(n = 0; n < 16; ++n)
        {
           out1[n] = clbufLeft[n] ^ ivbuf[n];
        }
        
        // printf("\n明文:");
        // dump_hex(out1,16);
        //一轮完成.........
        //iv = plbufLeft;
        for (size_t i = 0; i < 16; i++)//不能直接iv = plbufLeft，这样是修改指针的指向，而plbufLeft的值在循环前部改变了
        {
           ivbuf[i] = plbufLeft[i];
        }
        
        // printf("\n异或变量（上一次的密文）:");
        // dump_hex(iv,16);
        len -= 16;
        in1 += 32;
        out1 += 16;
    }
    if (len > 0){//不足16byte的数据在这里处理，有补全函数可以在这补全，len指的是明文长度
        for (n = 0; n < len; n++)
        {
           out1[n] = in1[n];
        }
        
    }
}