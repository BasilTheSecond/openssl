CC=cc
CFLAGS= -g -Wall -std=c99
LIBS=  -lcrypto
EXAMPLES=gcm

all: $(EXAMPLES) 

gcm: gcm.o
	$(CC) -o gcm gcm.o $(LIBS)

clean:	
	rm -f $(EXAMPLES) *.o

test: all
	@echo Test running gcm
	./gcm

