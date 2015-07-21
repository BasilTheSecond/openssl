#include <openssl/engine.h>
#include <string.h>

// RAND_bytes() is generated entirely by the RDRAND 
// instruction on Intel h/w
int main(int arc, char *argv[])
{ 
	ENGINE *engine;
	int rc;
	
	ENGINE_load_rdrand();
	
	engine= ENGINE_by_id("rdrand");
	
	if ( engine == NULL ) {
	  unsigned long err = ERR_get_error();
	  char *errstr = ERR_error_string(err, NULL);
  	printf("Error message: %s\n", errstr);
	  return 1;
	}
	
	rc = ENGINE_init(engine);
	
	if (rc != 1) {
	  unsigned long err = ERR_get_error();
	  char *errstr = ERR_error_string(err, NULL);
  	printf("Error message: %s\n", errstr);
	  return 1;
	}
	
	/* Set the engine as the default engine for random numbers */
	rc = ENGINE_set_default(engine, ENGINE_METHOD_RAND);
	
	if (rc != 1) {
	  unsigned long err = ERR_get_error();
	  char *errstr = ERR_error_string(err, NULL);
  	printf("Error message: %s\n", errstr);
	  return 1;
	}
	
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

	rc = RAND_bytes(buffer, sizeof(buffer));
	
	if (rc == 1)
		printf("strong randomness");
	else if (rc == 0)
		printf("weak randomness");


	if(rc != 1) {
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

	ENGINE_finish(engine);
	ENGINE_free(engine);
	ENGINE_cleanup();

  return 0;
}

