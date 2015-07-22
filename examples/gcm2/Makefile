CC=cc
CFLAGS= -g -Wall -std=c99
LIBS=  -lcrypto
EXAMPLES=gcm2

all: $(EXAMPLES) 

gcm2: gcm2.o
	$(CC) -o gcm2 gcm2.o $(LIBS)

clean:	
	rm -f $(EXAMPLES) *.o

test: all
	@echo Test running gcm2
	./gcm2

