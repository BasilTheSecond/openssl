CC=cc
CFLAGS= -g -Wall
LIBS=  -lcrypto
EXAMPLES=getting_started

all: $(EXAMPLES) 

getting_started: getting_started.o
	$(CC) -o getting_started getting_started.o $(LIBS)

clean:	
	rm -f $(EXAMPLES) *.o

test: all
	@echo Test running getting_started
	./getting_started

