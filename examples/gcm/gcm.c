#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

static int 
encrypt(unsigned char *plaintext, 
				int plaintext_len, 
				unsigned char *aad,
				int aad_len, 
				unsigned char *key, 
				unsigned char *iv,
				unsigned char *ciphertext, 
				unsigned char *tag);

static int 
decrypt(unsigned char *ciphertext, 
				int ciphertext_len, 
				unsigned char *aad,
				int aad_len, 
				unsigned char *tag, 
				unsigned char *key, 
				unsigned char *iv,
				unsigned char *plaintext);
				
static int
handleErrors(void);

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

  /* ... Do some crypto stuff here ... */
  
  for (int i = 0; i < argc; i++) {
		if (strcmp(argv[i], "-e") == 0) {
			
		}
		else if (strcmp(argv[i], "-d") == 0) {
	
		}
		i++;
  }

_exit:
  /* Clean up */

  /* Removes all digests and ciphers */
  EVP_cleanup();

  /* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
  CRYPTO_cleanup_all_ex_data();

  /* Remove error strings */
  ERR_free_strings();

  return rc;
}

static int 
encrypt(unsigned char *plaintext, 
				int plaintext_len, 
				unsigned char *aad,
				int aad_len, 
				unsigned char *key, 
				unsigned char *iv,
				unsigned char *ciphertext, 
				unsigned char *tag)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int ciphertext_len;


	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) {
		return handleErrors();
	}

	/* Initialise the encryption operation. */
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
		return handleErrors();
	}
	/* Set IV length if default 12 bytes (96 bits) is not appropriate */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL)) {
		return handleErrors();
	}

	/* Initialise key and IV */
	if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))  {
		return handleErrors();
	}

	/* Provide any AAD data. This can be called zero or more times as
	 * required
	 */
	if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) {
		return handleErrors();
	}

	/* Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
		return handleErrors();
	}
	ciphertext_len = len;

	/* Finalise the encryption. Normally ciphertext bytes may be written at
	 * this stage, but this does not occur in GCM mode
	 */
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
		return handleErrors();
	}
	ciphertext_len += len;

	/* Get the tag */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
		return handleErrors();
	}

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

static int 
decrypt(unsigned char *ciphertext, 
				int ciphertext_len, 
				unsigned char *aad,
				int aad_len, 
				unsigned char *tag, 
				unsigned char *key, 
				unsigned char *iv,
				unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;
	int ret;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) {
		return handleErrors();
	}

	/* Initialise the decryption operation. */
	if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
		return handleErrors();
	}

	/* Set IV length. Not necessary if this is 12 bytes (96 bits) */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL)) {
		return handleErrors();
	}

	/* Initialise key and IV */
	if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
		return handleErrors();
	}

	/* Provide any AAD data. This can be called zero or more times as
	 * required
	 */
	if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) {
		return handleErrors();
	}
	/* Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
		return handleErrors();
	}
	plaintext_len = len;

	/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) {
		return handleErrors();
	}

	/* Finalise the decryption. A positive return value indicates success,
	 * anything else is a failure - the plaintext is not trustworthy.
	 */
	ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	if(ret > 0)
	{
		/* Success */
		plaintext_len += len;
		return plaintext_len;
	}
	else
	{
		/* Verify failed */
		return -1;
	}
}

static int
handleErrors(void)
{
  unsigned long err = ERR_get_error();
  char *errstr = ERR_error_string(err, NULL);
	printf("Error message: %s\n", errstr);
	return -1;
}




