CC=cc
CFLAGS= -g -Wall -std=c99
LIBS=  -lcrypto
EXAMPLES=random_bytes

all: $(EXAMPLES) 

random_bytes: random_bytes.o
	$(CC) -o random_bytes random_bytes.o $(LIBS)

clean:	
	rm -f $(EXAMPLES) *.o

test: all
	@echo Test running random_bytes
	./random_bytes

