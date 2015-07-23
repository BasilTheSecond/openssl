#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <assert.h>

#define     TAG_SIZE    16

static unsigned char keybuf[32]; // 32 bytes for AES-256
static unsigned char ivbuf[16];
static int enclen, declen, declen2, enclen2;
static unsigned char encm[1024];
static unsigned char msg[1024];
static unsigned char decm[1024];
static unsigned char aad[1024]; // Additional associated data (can be any size)
static unsigned char tag[TAG_SIZE];

static int encrypt();
static int decrypt();

int 
main(	int argc, 
			char *argv[])
{

	int retv = encrypt();
	
	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}
	
	// Check that the authentication works
	//encm[0] ^= 0xff; // Tamper with the ciphertext
	//aad[0] ^= 0xff; // Tamper with the additional (plain-text) data
	
	retv = decrypt();

	// Check that ciphertext or AAD hasn't been tampered with
	if (retv == 1) {
		printf("Success\n");
	}
	else {
		printf("Fail\n");
	}
	
__exit:

  return retv == 1 ? 0 : 1;
}

static int
encrypt() {
	EVP_CIPHER_CTX *ctx     = EVP_CIPHER_CTX_new();
	
	assert(ctx != NULL);

	//Get the cipher.
	//const EVP_CIPHER *cipher  = EVP_aes_128_gcm ();
	const EVP_CIPHER *cipher  = EVP_aes_256_gcm ();
	
	// Generate shared key
	int retv = RAND_bytes(keybuf, sizeof(keybuf));
	
	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}
	
	// Generate IV
	retv = RAND_bytes(ivbuf, sizeof(ivbuf));
	
	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}
	
	memset(aad, 0, sizeof(aad));

	//Encrypt the data first.
	//Set the cipher and context only.
	retv    = EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL);

	//Set the nonce and tag sizes.
	//Set IV length. [Optional for GCM].

	retv    = EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(ivbuf), NULL);
	
	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}

	//Now initialize the context with key and IV. 
	retv    = EVP_EncryptInit_ex(ctx, NULL, NULL, (const unsigned char *)keybuf, (const unsigned char *)ivbuf);
	
	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}

	//[Optional for GCM]
	//Add Additional associated data (AAD). 
	// This can be called zero or more times as required
	retv    = EVP_EncryptUpdate(ctx, NULL, (int *)&enclen, (const unsigned char *)aad, sizeof(aad));

	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}
	
	//Now encrypt the data.
	// EVP_EncryptUpdate can be called multiple times if necessary
	retv    = EVP_EncryptUpdate(ctx, (unsigned char *)encm, (int *)&enclen, (const unsigned char *)msg, sizeof(msg));

	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}
	
	//Finalize.
	retv    = EVP_EncryptFinal_ex(ctx, (unsigned char *)encm + enclen, (int *)&enclen2);
	enclen  += enclen2;

	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}
	
	//printf("enclen=%d\n", enclen);


	//Get authentication tag
	retv    = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, (unsigned char *)tag);

	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}

__exit:

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);
	
	return retv;
}

static int
decrypt() {
	//DECRYPTION PART
	//Now Decryption of the data.
	//Then decrypt the data.

	
	EVP_CIPHER_CTX *ctx     = EVP_CIPHER_CTX_new();
	
	assert(ctx != NULL);
	
	//Get the cipher.
	//const EVP_CIPHER *cipher  = EVP_aes_128_gcm ();
	const EVP_CIPHER *cipher  = EVP_aes_256_gcm ();
	
	//Set just cipher.
	int retv    = EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL);

	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}

	//Set Nonce size.
	retv    = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(ivbuf), NULL);

	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}
	
	//Set key and IV (nonce).
	retv    = EVP_DecryptInit_ex(ctx, NULL, NULL, (const unsigned char*)keybuf, (const unsigned char *)ivbuf);

	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}

	//Set authentication tag
	retv    = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (unsigned char *)tag);

	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}
	
	//[Optional for GCM]
	//Add Additional associated data (AAD).
	// This can be called zero or more times as required
	retv    = EVP_DecryptUpdate(ctx, NULL, (int *)&declen, (const unsigned char *)aad, sizeof(aad));

	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}

	//Decrypt the data.
	// EVP_DecryptUpdate can be called multiple times if necessary
	retv    = EVP_DecryptUpdate(ctx, decm, (int *)&declen, (const unsigned char *)encm, enclen);

	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}
	
	//Finalize.
	retv    = EVP_DecryptFinal_ex(ctx, (unsigned char*)decm + declen, (int *)&declen2);

__exit:

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);
	
	return retv;
}

