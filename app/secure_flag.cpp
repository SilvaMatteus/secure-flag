#include <stdio.h>
#include <cstdlib>
#include <signal.h>
#include "sgx_urts.h"
#include "enclave_u.h"
#include "base64_utils.h"

#define SAFE_FREE( ptr ) { if ( ( NULL !=  ptr )  && ( nullptr != ptr ) ) { free( ptr ); ( ptr ) = NULL; } }
#define ENCLAVE_NAME "enclave.signed.so"
#define AES_GCM_IV_SIZE 12
#define AES_CTR_IV_SIZE 16
#define AES_GCM_MAC_SIZE 16

using namespace std;

/* Global variables */
sgx_status_t sgx_status;
sgx_enclave_id_t eid;
sgx_launch_token_t launch_token;
int updated = 0;
bool invalid_params = false;

/* Signal handler */
void my_handler( int s )
{
    printf( "\nGood bye!\n" );
    /* Cleaning up */
    sgx_destroy_enclave( eid );
    exit(s); 
}

void print_byte_array_ocall( void *mem, size_t len )
{
    int i, count=0;
    uint8_t *array = ( uint8_t * ) mem;
    for ( i=0; i<len; i++ )
    {
        if ( count == 0 ) printf( "\n" );
        count = ( count + 1 ) % 8;
        printf( "0x%x", array[i] );
        if ( i+1 < len ) printf( ", " );
    }
    printf( "\n" );
}

void print_string_ocall( char *str )
{
    fprintf( stdout, str );
}

void enter_flag( char *p_flag )
{
    sgx_status_t first_status, second_status;
    size_t flag_size = strlen( p_flag );
    
#ifdef AES_GCM

    uint8_t *p_iv_mac_enc_flag = (uint8_t *) malloc( AES_GCM_IV_SIZE + AES_GCM_MAC_SIZE + flag_size );
    size_t iv_mac_enc_flag_size = AES_GCM_IV_SIZE + AES_GCM_MAC_SIZE + flag_size;
    
    first_status = encrypt_flag_ecall(
        eid, &second_status,
        (uint8_t *) p_flag,
        flag_size,
        p_iv_mac_enc_flag,
        iv_mac_enc_flag_size
    );

    if ( first_status != SGX_SUCCESS )
    {
        printf( "\nAES_GCM failed!\n" );
    }
    char *p_b64_encrypted_flag = (char *) calloc( iv_mac_enc_flag_size, 2 );
    base64encode( p_iv_mac_enc_flag, iv_mac_enc_flag_size, p_b64_encrypted_flag, iv_mac_enc_flag_size * 2 );
    SAFE_FREE( p_iv_mac_enc_flag );

#endif // AES_GCM

#ifdef AES_CTR

    uint8_t *p_iv_enc_ctr_flag = (uint8_t *) malloc( AES_CTR_IV_SIZE + flag_size );
    size_t iv_enc_ctr_flag_size = AES_CTR_IV_SIZE + flag_size;

    first_status = encrypt_flag_aes_ctr_ecall(
        eid, &second_status,
        (uint8_t *) p_flag,
        flag_size,
        p_iv_enc_ctr_flag,
        iv_enc_ctr_flag_size
    );

    if ( first_status != SGX_SUCCESS )
    {
        printf( "\nAES_CTR failed!\n" );
    }
    char *p_b64_encrypted_flag = (char *) calloc( iv_enc_ctr_flag_size, 2 );
    base64encode( p_iv_enc_ctr_flag, iv_enc_ctr_flag_size, p_b64_encrypted_flag, iv_enc_ctr_flag_size * 2 );
    SAFE_FREE( p_iv_enc_ctr_flag );

#endif // AES_CTR

    printf( "%s\n", p_b64_encrypted_flag );
    SAFE_FREE( p_b64_encrypted_flag );
}

void retrieve_flag( char *p_b64_enc_flag )
{
    sgx_status_t first_status, second_status;
    size_t max_len = strlen( p_b64_enc_flag );
    size_t flag_size = max_len;
    char *p_flag = (char*) calloc( max_len, 1 );

#ifdef AES_GCM

    uint8_t *p_iv_mac_encrypted_flag = (uint8_t *) calloc( max_len, 1 );
    size_t iv_mac_enc_flag_size = max_len;

    base64decode( p_b64_enc_flag, strlen( p_b64_enc_flag ), p_iv_mac_encrypted_flag, &iv_mac_enc_flag_size );
    first_status = decrypt_flag_ecall(
        eid, &second_status,
        p_iv_mac_encrypted_flag,
        iv_mac_enc_flag_size,
        (uint8_t *) p_flag,
        flag_size
    );
    if ( first_status != SGX_SUCCESS || second_status != SGX_SUCCESS )
    {
        printf( "\nAES_GCM Failed!\n" );
    }
    SAFE_FREE( p_iv_mac_encrypted_flag );

#endif // AES_GCM

#ifdef AES_CTR

    uint8_t *p_iv_ctr_encrypted_flag = (uint8_t *) calloc( max_len, 1 );
    size_t iv_ctr_enc_flag_size = max_len;

    base64decode( p_b64_enc_flag, strlen( p_b64_enc_flag ), p_iv_ctr_encrypted_flag, &iv_ctr_enc_flag_size );
    first_status = decrypt_flag_aes_ctr_ecall(
        eid, &second_status,
        p_iv_ctr_encrypted_flag,
        iv_ctr_enc_flag_size,
        (uint8_t *) p_flag,
        flag_size
    );
    if ( first_status != SGX_SUCCESS || second_status != SGX_SUCCESS )
    {
        printf( "\nAES_CTR Failed!\n" );
    }
    SAFE_FREE( p_iv_ctr_encrypted_flag );

#endif //AES_CTR

    printf( "%s\n", p_flag);
    SAFE_FREE( p_flag );
}

void show_usage()
{
    int option;
    printf( "\nOptions:\n" );
    printf( "   store [ -s ] <flag>  ---> save a flag.\n" );
    printf( "   retrieve [ -r ] <encrypted flag>  ---> retrieve a flag.\n" );
}

#ifndef QUIET_MODE
void show_header()
{
    FILE *header = fopen ( "README.md", "r" );
    char *str_header = (char *) calloc( 91, 1 );
    for ( int i = 0; i < 11; i++ )
    {
        fgets ( str_header , 90, header );
        printf( "%s", str_header );
    }
    SAFE_FREE( str_header );
}
#endif // QUIET_MODE

int main( int argc, char *argv[] )
{
#ifndef QUIET_MODE
    show_header();
#endif // QUIET_MODE

    if ( argc != 3 )
        invalid_params = true;
    if ( invalid_params )
    {
        show_usage();
        return EXIT_SUCCESS;
    }

    /* Wait for kill signal */
    struct sigaction sigIntHandler;
    sigIntHandler.sa_handler = my_handler;
    sigemptyset( &sigIntHandler.sa_mask );
    sigIntHandler.sa_flags = 0;
    sigaction( SIGINT, &sigIntHandler, NULL );
    
    /* Create SGX enclave */
    sgx_status = sgx_create_enclave(
        ENCLAVE_NAME,
        SGX_DEBUG_FLAG,
        &launch_token,
        &updated,
        &eid,
        NULL
    );

    if ( sgx_status != SGX_SUCCESS )
    {
        printf( "\nUnable to create enclave. Exiting...\n" );
        exit( -1 );
    }

    if ( strcmp( argv[1], "store" ) == 0 || strcmp( argv[1], "-s" ) == 0 )
    {
        enter_flag( argv[2] );
    }
    else if ( strcmp( argv[1], "retrieve" ) == 0 || strcmp( argv[1], "-r" ) == 0 )
    {
        retrieve_flag( argv[2] );
    }
    else
    {
        show_usage();
    }
    sgx_destroy_enclave( eid );
    return sgx_status;
}
