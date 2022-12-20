#include"sm4_expand.h"
#include"util.h"

int main(){
    uint8_t *key={"12345678901234567890123456789012"};
    SM4_EXPAND_KEY *ks;
    ks = (SM4_EXPAND_KEY*)malloc(sizeof(SM4_EXPAND_KEY));
    sm4_expand_set_key(key,ks);
    uint8_t data[16]={"1234567890123456"};
    uint8_t data_encrypted[17];
    uint8_t data_decrypted[17];
    
    printf("original data:\n");
    dump_hex(data,16);
    sm4_expand_encrypt(data,data_encrypted,ks);
    printf("encrypted data:\n");
    dump_hex(data_encrypted,16);
    
    sm4_expand_decrypt(data_encrypted,data_decrypted,ks);
    printf("decrypted data:\n");
    dump_hex(data_decrypted,16);
    
    return 0;
}