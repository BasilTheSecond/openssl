#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>

#define     TAG_SIZE    16

int 
main(	int argc, 
			char *argv[])
{
	EVP_CIPHER_CTX *ctx     = EVP_CIPHER_CTX_new();

	//Get the cipher.
	//const EVP_CIPHER *cipher  = EVP_aes_128_gcm ();
	const EVP_CIPHER *cipher  = EVP_aes_256_gcm ();

	unsigned char keybuf[32]; // 32 bytes for AES-256
	unsigned char ivbuf[16];
	int enclen, declen, declen2, enclen2;
	unsigned char encm[1024];
	unsigned char msg[1024];
	unsigned char decm[1024];
	unsigned char aad[1024]; // Additional associated data (can be any size)
	unsigned char tag[TAG_SIZE];
	
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

	//Add Additional associated data (AAD). [Optional for GCM]
	retv    = EVP_EncryptUpdate (ctx, NULL, (int *)&enclen, (const unsigned char *)aad, sizeof(aad));

	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}
	
	//Now encrypt the data.
	retv    = EVP_EncryptUpdate (ctx, (unsigned char *)encm, (int *)&enclen, (const unsigned char *)msg, sizeof(msg));

	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}
	
	//Finalize.
	retv    = EVP_EncryptFinal (ctx, (unsigned char *)encm + enclen, (int *)&enclen2);
	enclen  += enclen2;

	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}
	
	//printf("enclen=%d\n", enclen);
	
	// Check that authentication
	//encm[0] ^= 0xff; // Corrupt the cipertext
	//aad[0] ^= 0xff; // Corrupt the additional (plain-text) data

	//Get authentication tag
	retv    = EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, (unsigned char *)tag);

	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}

	//DECRYPTION PART
	//Now Decryption of the data.
	//Then decrypt the data.
	//Set just cipher.
	retv    = EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL);

	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}

	//Set Nonce size.
	retv    = EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(ivbuf), NULL);

	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}

	//Set authentication tag
	retv    = EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (unsigned char *)tag);

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

	//Add Additional associated data (AAD).
	retv    = EVP_DecryptUpdate (ctx, NULL, (int *)&declen, (const unsigned char *)aad, sizeof(aad));

	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}

	//Decrypt the data.
	retv    = EVP_DecryptUpdate (ctx, decm, (int *)&declen, (const unsigned char *)encm, enclen);

	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}
	
	//Finalize.
	retv    = EVP_DecryptFinal (ctx, (unsigned char*)decm + declen, (int *)&declen2);

	if (retv == 1) {
		printf("Success\n");
	}
	else {
		printf("Fail\n");
	}

__exit:  
  /* Clean up */
  
  EVP_CIPHER_CTX_free(ctx);

  /* Removes all digests and ciphers */
  EVP_cleanup();

  return retv == 1 ? 0 : 1;
}


