#include "enclave_t.h"
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include <string.h>

#define AES_GCM_IV_SIZE 12
#define AES_CTR_IV_SIZE 16
#define AES_GCM_KEY_SIZE 16
#define AES_GCM_MAC_SIZE 16

#define SAFE_FREE( ptr ) { if ( ( NULL !=  ptr )  && ( nullptr != ptr ) ) { free( ptr ); ( ptr ) = NULL; } }

uint8_t p_shared_key[AES_GCM_KEY_SIZE] = { 
    0x65, 0x3c, 0x2b, 0x9a, 0x4c, 0x86, 0x10, 0xc4,
    0x07, 0x50, 0x02, 0x67, 0x90, 0xe8, 0x3d, 0xe0
};

sgx_status_t encrypt_flag_ecall( uint8_t *p_flag, size_t flag_size,  uint8_t *p_iv_mac_enc_flag, size_t encrypted_size )
{   
    sgx_status_t return_status;
    return_status = sgx_read_rand( (uint8_t *) p_iv_mac_enc_flag, AES_GCM_IV_SIZE );
    if ( return_status != SGX_SUCCESS )
    {
        return return_status;
    }
    return_status = sgx_rijndael128GCM_encrypt(
        (sgx_aes_gcm_128bit_key_t *) p_shared_key,
        p_flag,
        (uint32_t) flag_size,
        p_iv_mac_enc_flag + AES_GCM_IV_SIZE + AES_GCM_MAC_SIZE,
        p_iv_mac_enc_flag,
        (uint32_t) AES_GCM_IV_SIZE, 
        NULL,
        0,
        (sgx_aes_gcm_128bit_tag_t*) (p_iv_mac_enc_flag + AES_GCM_IV_SIZE)
    );
    return return_status;
}

sgx_status_t encrypt_flag_aes_ctr_ecall( uint8_t *p_flag, size_t flag_size,  uint8_t *p_iv_enc_ctr_flag, size_t iv_enc_ctr_flag_size )
{
    sgx_status_t return_status;
    uint8_t *p_tmp_iv = (uint8_t *) malloc( AES_CTR_IV_SIZE );

    return_status = sgx_read_rand( (uint8_t *) p_tmp_iv, AES_CTR_IV_SIZE );
    memcpy(p_iv_enc_ctr_flag, p_tmp_iv, 16);
    
    if ( return_status != SGX_SUCCESS )
    {
        return return_status;
    }
    return_status = sgx_aes_ctr_encrypt(
        (sgx_aes_ctr_128bit_key_t *) p_shared_key,
        p_flag,
        ( uint32_t ) flag_size,
        p_tmp_iv,
        ( uint32_t ) AES_CTR_IV_SIZE,
        p_iv_enc_ctr_flag + AES_CTR_IV_SIZE
    );
    SAFE_FREE( p_tmp_iv );
    return return_status;
}

sgx_status_t decrypt_flag_ecall( uint8_t *p_iv_mac_encrypted_flag, size_t encrypted_flag_size, uint8_t *p_flag, size_t flag_size )
{
    sgx_status_t return_status;
    sgx_rijndael128GCM_decrypt(
        (sgx_aes_gcm_128bit_key_t *) p_shared_key,
        p_iv_mac_encrypted_flag + AES_GCM_IV_SIZE + AES_GCM_MAC_SIZE,
        (uint32_t) ( encrypted_flag_size - AES_GCM_IV_SIZE - AES_GCM_MAC_SIZE ),
        p_flag,
        p_iv_mac_encrypted_flag,
        (uint32_t) AES_GCM_IV_SIZE,
        NULL,
        0,
        (sgx_aes_gcm_128bit_tag_t*) (p_iv_mac_encrypted_flag + AES_GCM_IV_SIZE)
    );
    return return_status;
}

sgx_status_t decrypt_flag_aes_ctr_ecall( uint8_t *p_iv_ctr_encrypted_flag, size_t iv_ctr_enc_flag_size, uint8_t *p_flag, size_t flag_size )
{
    sgx_status_t return_status;
    sgx_aes_ctr_decrypt(
        (sgx_aes_ctr_128bit_key_t *) p_shared_key,
        p_iv_ctr_encrypted_flag + AES_CTR_IV_SIZE,
        ( uint32_t ) ( iv_ctr_enc_flag_size - AES_CTR_IV_SIZE ),
        p_iv_ctr_encrypted_flag,
        ( uint32_t ) AES_GCM_IV_SIZE,
        p_flag
    );
    return return_status;
}