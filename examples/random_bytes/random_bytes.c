#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/engine.h>
#include <string.h>

int main(int arc, char *argv[])
{ 
  /* Load the human readable error strings for libcrypto */
  ERR_load_crypto_strings();

  /* Load all digest and cipher algorithms */
  OpenSSL_add_all_algorithms();

  /* Load config file, and other important initialisation */
  OPENSSL_config(NULL);

  /* ... Do some crypto stuff here ... */
	unsigned char buffer[128];
	
	memset(buffer, 0, sizeof(buffer));
	
	#if 0
	for (int i = 0; i < sizeof(buffer); i++) {
		if ((i % 16) == 0) {
			printf("\n");
		}
		printf("%02x ", buffer[i]);
	}
	#endif
	
	printf("\n");

	/* RAND_bytes() automatically calls RAND_poll()
	 */
	int rc = RAND_bytes(buffer, sizeof(buffer));
	
	if (rc == 1)
		printf("strong randomness");
	else if (rc == 0)
		printf("weak randomness");
	

	if(rc != 1) {
		  /* RAND_bytes failed */
		  /* `err` is valid    */
		  unsigned long err = ERR_get_error();
		  char *errstr = ERR_error_string(err, NULL);
    	printf("Error message: %s\n", errstr);
		  return 1;
	}

	/* OK to proceed */
	
	for (int i = 0; i < sizeof(buffer); i++) {
		if ((i % 16) == 0) {
			printf("\n");
		}
		printf("%02x ", buffer[i]);
	}
	
	printf("\n");

  /* Clean up */

  /* Removes all digests and ciphers */
  EVP_cleanup();

  /* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
  CRYPTO_cleanup_all_ex_data();

  /* Remove error strings */
  ERR_free_strings();

  return 0;
}

