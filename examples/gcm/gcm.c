#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

//#define DUMP_ALL // NOTE: use ./gcm | hexdump -C
#define TAG_SIZE 16
#define IV_SIZE 16
#define KEY_SIZE 32 // 32 bytes for AES-256
#define MESSAGE_SIZE 128//1024
#define AAD_MESSAGE_SIZE 128 //1024 // Additional associated data (must be divisible by 32)

static EVP_CIPHER *cipher = NULL;
static int enclen, declen, declen2, enclen2;
static unsigned char keybuf[KEY_SIZE]; 
static unsigned char ivbuf[IV_SIZE];
static unsigned char encm[MESSAGE_SIZE];
static unsigned char msg[MESSAGE_SIZE];
static unsigned char decm[MESSAGE_SIZE];
static unsigned char aad[AAD_MESSAGE_SIZE];
static unsigned char tag[TAG_SIZE];

static int encrypt();
static int decrypt();

#if defined(DUMP_ALL)
static void dump(	const char *str,
									const void *buf, 
									size_t count);
#else
#define dump(...)
#endif

int 
main(	int argc, 
			char *argv[])
{
	//Select the cipher.
	//cipher  = EVP_aes_128_gcm ();
	cipher  = (EVP_CIPHER *)EVP_aes_256_gcm ();
	
	// Clear buffers (optional)
	memset(keybuf, 0, sizeof(keybuf));
	memset(ivbuf, 0, sizeof(ivbuf));
	memset(encm, 0, sizeof(encm));
	memset(msg, 0, sizeof(msg));
	memset(decm, 0, sizeof(decm));	
	memset(aad, 0, sizeof(aad));
	memset(tag, 0, sizeof(tag));
	
	// Generate the shared key
	int retv = RAND_bytes(keybuf, sizeof(keybuf));
	
	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}
	
	dump("keybuf:---------", keybuf, sizeof(keybuf));
	
	// Generate the IV (nonce)
	retv = RAND_bytes(ivbuf, sizeof(ivbuf));
	
	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}
	
	dump("ivbuf:----------", ivbuf, sizeof(ivbuf));
	
	// Prepare the additional associated data (AAD)
	retv = RAND_bytes(aad, sizeof(aad));
	
	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}
	
	dump("aad:------------", aad, sizeof(aad));
	
	// Prepare the plaintext
	retv = RAND_bytes(msg, sizeof(msg));
	
	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}
	
	dump("msg:------------", msg, sizeof(msg));

	retv = encrypt();
	
	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}
	
	dump("encm:-----------", encm, sizeof(encm));
	dump("tag:------------", tag, sizeof(tag));
	
	// Check that the authentication works
	//encm[0] ^= 0xff; // Tamper with the ciphertext
	//aad[0] ^= 0xff; // Tamper with the additional (plain-text) data
	
	retv = decrypt();
	
	dump("decm:-----------", decm, sizeof(decm));

	// Check that ciphertext or AAD hasn't been tampered with
	if (retv == 1 && memcmp(msg, decm, declen) == 0) {
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
	// Create and initialize the context
	EVP_CIPHER_CTX evp_cipher_ctx;
	EVP_CIPHER_CTX *ctx = &evp_cipher_ctx;
  EVP_CIPHER_CTX_init(ctx);
  
	assert(cipher != NULL);
	
	// Set the cipher and context
	int retv = EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL);

	// Set IV (nonce) size
	retv = EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(ivbuf), NULL);
	
	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}

	// Set the key and IV (nonce)
	retv = EVP_EncryptInit_ex(ctx, NULL, NULL, (const unsigned char *)keybuf, (const unsigned char *)ivbuf);
	
	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}

	// Add AAD
	// NOTE: Called zero (when there is no AAD) or more times as required
	retv = EVP_EncryptUpdate(ctx, NULL, (int *)&enclen, (const unsigned char *)aad, sizeof(aad));

	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}
	
	// Encrypt the data
	// NOTE: Can be called multiple times if necessary
	retv = EVP_EncryptUpdate(ctx, (unsigned char *)encm, (int *)&enclen, (const unsigned char *)msg, sizeof(msg));

	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}
	
	// Finalize
	retv = EVP_EncryptFinal_ex(ctx, (unsigned char *)encm + enclen, (int *)&enclen2);
	enclen += enclen2;

	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}

	// Get the authentication tag
	retv = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, (unsigned char *)tag);

	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}

__exit:
	// Scrubb the memory and release the context
	EVP_CIPHER_CTX_cleanup(ctx); 
	
	return retv;
}

static int
decrypt() {
	// Create and initialize the context
	EVP_CIPHER_CTX evp_cipher_ctx;
	EVP_CIPHER_CTX *ctx = &evp_cipher_ctx;
  EVP_CIPHER_CTX_init(ctx);
	
	assert(cipher != NULL);
	
	// Set the cipher and context
	int retv = EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL);

	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}

	// Set the IV (nonce) size
	retv = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(ivbuf), NULL);

	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}
	
	// Set the key and IV (nonce)
	retv = EVP_DecryptInit_ex(ctx, NULL, NULL, (const unsigned char*)keybuf, (const unsigned char *)ivbuf);

	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}

	// Set the authentication tag
	retv = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (unsigned char *)tag);

	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}
	
	// Add AAD
	// NOTE: Called zero (when there is no AAD) or more times as required
	retv = EVP_DecryptUpdate(ctx, NULL, (int *)&declen, (const unsigned char *)aad, sizeof(aad));

	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}

	// Decrypt the data
	// NOTE: Can be called multiple times if necessary
	retv = EVP_DecryptUpdate(ctx, decm, (int *)&declen, (const unsigned char *)encm, enclen);

	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}
	
	// Finalize
	retv = EVP_DecryptFinal_ex(ctx, (unsigned char*)decm + declen, (int *)&declen2);
	
	declen += declen2;

__exit:
	// Scrubb the memory and release the context
	EVP_CIPHER_CTX_cleanup(ctx); 
	
	return retv;
}

#if defined(DUMP_ALL)
static void 
dump(	const char *str,
			const void *buf, 
			size_t count) {
	if (str != NULL) {
		write(1, str, strlen(str));
	}
	write(1, buf, count);
}
#endif

