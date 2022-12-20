/*
 * @Descripttion : 
 * @Version      : 
 * @Autor        : one30
 * @Date         : 2022-04-14 21:51:25
 * @LastEditTime: 2022-11-02 07:57:17
 * @FilePath: /sm4_256/include/lut_sm4_lai_massey.h
 */

#ifndef LUT_SM4_LM_H
#define LUT_SM4_LM_H

#include <stdint.h>
/**
 * @brief SM4 roundkey
 */
typedef uint32_t* SM4_Key;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief init SM4 roundKey
 * @param key 128bit key
 * @param sm4_key SM4 roundKey pointer
 * @return 1 if success, 0 if error
 */
int SM4_LM_KeyInit(uint8_t* key, SM4_Key* sm4_key);

/**
 * @brief SM4 Encrypt
 * @param plaintext 
 * @param ciphertext 
 * @param sm4_key
 */
void SM4_LM_Encrypt(uint8_t* plaintext, uint8_t* ciphertext, SM4_Key sm4_key);

/**
 * @brief SM4 Decrypt
 * @param ciphertext 
 * @param plaintextt 
 * @param sm4_key
 */
void SM4_LM_Decrypt(uint8_t* ciphertext, uint8_t* plaintext, SM4_Key sm4_key);

/**
 * @brief delete SM4 roundKey
 * @param sm4_key SM4 roundKey
 */
void SM4_KeyDelete(SM4_Key sm4_key);

#ifdef __cplusplus
}
#endif

#endif //LUT_SM4_H