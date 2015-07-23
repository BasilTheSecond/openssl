#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>

#define     GCM_ADD     "0000"
#define     TAG_SIZE    16

int 
main(	int argc, 
			char *argv[])
{
	EVP_CIPHER_CTX *ctx     = EVP_CIPHER_CTX_new();

	//Get the cipher.
	const EVP_CIPHER *cipher  = EVP_aes_128_gcm ();

	unsigned char keybuf[32]; // 32 bytes for AES-256
	unsigned char ivbuf[16];
	int enclen, declen, declen2, enclen2;
	unsigned char encm[1024];
	unsigned char msg[1024];
	unsigned char decm[1024];
	
	// Create shared key
	memset(keybuf, 0, sizeof(keybuf));
	
	int retv = RAND_bytes(keybuf, sizeof(keybuf));
	
	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}
	
	// Create IV
	memset(ivbuf, 0, sizeof(ivbuf));
	
	retv = RAND_bytes(ivbuf, sizeof(ivbuf));
	
	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}


	//Encrypt the data first.
	//Set the cipher and context only.
	retv    = EVP_EncryptInit (ctx, cipher, NULL, NULL);

	//Set the nonce and tag sizes.
	//Set IV length. [Optional for GCM].

	retv    = EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(ivbuf), NULL);
	
	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}

	//Now initialize the context with key and IV. 
	retv    = EVP_EncryptInit (ctx, NULL, (const unsigned char *)keybuf, (const unsigned char *)ivbuf);
	
	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}

	//Add Additional associated data (AAD). [Optional for GCM]
	retv    = EVP_EncryptUpdate (ctx, NULL, (int *)&enclen, (const unsigned char *)GCM_ADD, strlen(GCM_ADD));

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
	
	//encm[0] ^= 0xff; // Corrupt the message to check that authentication works

	//Append authentication tag at the end.
	retv    = EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, (unsigned char *)encm + enclen);

	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}

	//DECRYPTION PART
	//Now Decryption of the data.
	//Then decrypt the data.
	//Set just cipher.
	retv    = EVP_DecryptInit(ctx, cipher, NULL, NULL);

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

	//Set Tag from the data.
	retv    = EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (unsigned char *)encm + enclen);

	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}

	//Set key and IV (nonce).
	retv    = EVP_DecryptInit (ctx, NULL, (const unsigned char*)keybuf, (const unsigned char *)ivbuf);

	if (retv != 1) {
		printf("Error\n");
		goto __exit;
	}

	//Add Additional associated data (AAD).
	retv    = EVP_DecryptUpdate (ctx, NULL, (int *)&declen, (const unsigned char *)GCM_ADD,
			                         strlen((const char *)GCM_ADD));

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

  /* Removes all digests and ciphers */
  EVP_cleanup();

  return retv == 1 ? 0 : 1;
}


