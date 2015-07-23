#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#define     GCM_IV      "000000000000"
#define     GCM_ADD     "0000"
#define     TAG_SIZE    16
#define     ENC_SIZE    64

int 
main(	int argc, 
			char *argv[])
{ 
	int rc = 0;
	
  /* Load the human readable error strings for libcrypto */
  ERR_load_crypto_strings();

  /* Load all digest and cipher algorithms */
  OpenSSL_add_all_algorithms();

  /* Load config file, and other important initialisation */
  OPENSSL_config(NULL);

	EVP_CIPHER_CTX *ctx     = EVP_CIPHER_CTX_new();

	//Get the cipher.
	const EVP_CIPHER *cipher  = EVP_aes_128_gcm ();



	
	unsigned char keybuf[1024];
	int enclen, declen, declen2, enclen2;
	unsigned char encm[1024];
	unsigned char msg[1024];
	unsigned char decm[1024];


	//Encrypt the data first.
	//Set the cipher and context only.
	int retv    = EVP_EncryptInit (ctx, cipher, NULL, NULL);
	
	(void)retv;

	//Set the nonce and tag sizes.
	//Set IV length. [Optional for GCM].

	retv    = EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_IVLEN, strlen((const char *)GCM_IV), NULL);

	//Now initialize the context with key and IV. 
	retv    = EVP_EncryptInit (ctx, NULL, (const unsigned char *)keybuf, (const unsigned char *)GCM_IV);

	//Add Additional associated data (AAD). [Optional for GCM]
	retv    = EVP_EncryptUpdate (ctx, NULL, (int *)&enclen, (const unsigned char *)GCM_ADD, strlen(GCM_ADD));

	//Now encrypt the data.
	retv    = EVP_EncryptUpdate (ctx, (unsigned char *)encm, (int *)&enclen, (const unsigned char *)msg, sizeof(msg));

	//Finalize.
	retv    = EVP_EncryptFinal (ctx, (unsigned char *)encm + enclen, (int *)&enclen2);
	enclen  += enclen2;


	//Append authentication tag at the end.
	retv    = EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, (unsigned char *)encm + enclen);

	//DECRYPTION PART
	//Now Decryption of the data.
	//Then decrypt the data.
	//Set just cipher.
	retv    = EVP_DecryptInit(ctx, cipher, NULL, NULL);

	//Set Nonce size.
	retv    = EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_IVLEN, strlen((const char *)GCM_IV), NULL);

	//Set Tag from the data.
	retv    = EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (unsigned char *)encm + enclen);

	//Set key and IV (nonce).
	retv    = EVP_DecryptInit (ctx, NULL, (const unsigned char*)keybuf, (const unsigned char *)GCM_IV);

	//Add Additional associated data (AAD).
	retv    = EVP_DecryptUpdate (ctx, NULL, (int *)&declen, (const unsigned char *)GCM_ADD,
			                         strlen((const char *)GCM_ADD));

	//Decrypt the data.
	retv    = EVP_DecryptUpdate (ctx, decm, (int *)&declen, (const unsigned char *)encm, enclen);


	//Finalize.
	retv    = EVP_DecryptFinal (ctx, (unsigned char*)decm + declen, (int *)&declen2);
	
	if (retv == 1) {
		printf("Success\n");
	}
	else {
		printf("Fail\n");
	}
  
  /* Clean up */

  /* Removes all digests and ciphers */
  EVP_cleanup();

  /* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
  CRYPTO_cleanup_all_ex_data();

  /* Remove error strings */
  ERR_free_strings();

  return rc;
}


