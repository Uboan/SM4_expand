#include<sm4_cbc.h>

void sm4_cbc_set_key(const uint8_t *key2,SM4_KEY *ks){
    ossl_sm4_set_key(key2,ks);
}

void sm4_cbc_encrypt(uint8_t *in,uint8_t *out,uint8_t *ivec,size_t len,SM4_KEY *ks){
    
    size_t n; 
    uint8_t * out1 = out;
    unsigned char plbuf[16];//输入缓存
    unsigned char ivbuf[16];//异或变量缓存
    unsigned char clbuf[16];//输出缓存
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
            plbuf[n] = in1[n] ^ ivbuf[n];//缓存:明文与初始变量进行异或
           //key everytime
            
        }
        // printf("\n明文异或：");
        // dump_hex(plbufLeft, 16);
        ossl_sm4_encrypt(plbuf,clbuf,ks);
        // printf("\n密文：");
        // dump_hex(clbufLeft, 16);
        // printf("\nR8：");
        // dump_hex(clbufRight, 16);
        for(n = 0; n < 16; ++n)
        {
            out1[n] = clbuf[n]; 
        }
        // printf("\n密文+r8：");
        // dump_hex(out1, 32);
        //一轮完成.........
        for (size_t i = 0; i < 16; i++)
        {
            ivbuf[i] = clbuf[i]; 
        }
        
        // printf("\n加密iv:");
        // dump_hex(iv, 16);
        len -= 16;
        in1 += 16;
        out1 += 16;
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

void sm4_cbc_decrypt(uint8_t *in,uint8_t *out,uint8_t *ivec,size_t len,SM4_KEY *ks){
    
    size_t n; 
    uint8_t * out1 = out;
    unsigned char plbuf[16];//输入缓存
    unsigned char clbuf[16];//输出缓存
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
           plbuf[n] = in1[n];
            
        }
        ossl_sm4_decrypt(plbuf,clbuf,ks);
        // printf("\nkey1:");
        // dump_hex(clbufRight,16);
        // printf("\n明文异或后的值:");
        // dump_hex(clbufLeft,16);
        //  printf("\n异或变量:");
        // dump_hex(iv,16);
        for(n = 0; n < 16; ++n)
        {
           out1[n] = clbuf[n] ^ ivbuf[n];
        }
        
        // printf("\n明文:");
        // dump_hex(out1,16);
        //一轮完成.........
        //iv = plbufLeft;
        for (size_t i = 0; i < 16; i++)//不能直接iv = plbufLeft，这样是修改指针的指向，而plbufLeft的值在循环前部改变了
        {
           ivbuf[i] = plbuf[i];
        }
        
        // printf("\n异或变量（上一次的密文）:");
        // dump_hex(iv,16);
        len -= 16;
        in1 += 16;
        out1 += 16;
    }
    if (len > 0){//不足16byte的数据在这里处理，有补全函数可以在这补全，len指的是明文长度
        for (n = 0; n < len; n++)
        {
           out1[n] = in1[n];
        }
        
    }
}


void sm4_expand_cbc_set_key(const uint8_t *key2,SM4_EXPAND_KEY *ks){
    sm4_expand_set_key(key2,ks);
}

void sm4_expand_cbc_encrypt(uint8_t *in,uint8_t *out,uint8_t *ivec,size_t len,SM4_EXPAND_KEY *ks){
    
    size_t n; 
    uint8_t * out1 = out;
    unsigned char plbuf[16];//输入缓存
    unsigned char ivbuf[16];//异或变量缓存
    unsigned char clbuf[16];//输出缓存
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
            plbuf[n] = in1[n] ^ ivbuf[n];//缓存:明文与初始变量进行异或
           //key everytime
            
        }
        // printf("\n明文异或：");
        // dump_hex(plbufLeft, 16);
        sm4_expand_encrypt(plbuf,clbuf,ks);
        // printf("\n密文：");
        // dump_hex(clbufLeft, 16);
        // printf("\nR8：");
        // dump_hex(clbufRight, 16);
        for(n = 0; n < 16; ++n)
        {
            out1[n] = clbuf[n]; 
        }
        // printf("\n密文+r8：");
        // dump_hex(out1, 32);
        //一轮完成.........
        for (size_t i = 0; i < 16; i++)
        {
            ivbuf[i] = clbuf[i]; 
        }
        
        // printf("\n加密iv:");
        // dump_hex(iv, 16);
        len -= 16;
        in1 += 16;
        out1 += 16;
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

void sm4_expand_cbc_decrypt(uint8_t *in,uint8_t *out,uint8_t *ivec,size_t len,SM4_EXPAND_KEY *ks){
    
    size_t n; 
    uint8_t * out1 = out;
    unsigned char plbuf[16];//输入缓存
    unsigned char clbuf[16];//输出缓存
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
           plbuf[n] = in1[n];
            
        }
        sm4_expand_decrypt(plbuf,clbuf,ks);
        
        // printf("\nkey1:");
        // dump_hex(clbufRight,16);
        // printf("\n明文异或后的值:");
        // dump_hex(clbufLeft,16);
        //  printf("\n异或变量:");
        // dump_hex(iv,16);
        for(n = 0; n < 16; ++n)
        {
           out1[n] = clbuf[n] ^ ivbuf[n];
        }
        
        // printf("\n明文:");
        // dump_hex(out1,16);
        //一轮完成.........
        //iv = plbufLeft;
        for (size_t i = 0; i < 16; i++)//不能直接iv = plbufLeft，这样是修改指针的指向，而plbufLeft的值在循环前部改变了
        {
           ivbuf[i] = plbuf[i];
        }
        
        // printf("\n异或变量（上一次的密文）:");
        // dump_hex(iv,16);
        len -= 16;
        in1 += 16;
        out1 += 16;
    }
    if (len > 0){//不足16byte的数据在这里处理，有补全函数可以在这补全，len指的是明文长度
        for (n = 0; n < len; n++)
        {
           out1[n] = in1[n];
        }
        
    }
}