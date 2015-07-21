CC=cc
CFLAGS= -g -Wall -std=c99
LIBS=  -lcrypto
EXAMPLES=random_engine

all: $(EXAMPLES) 

random_engine: random_engine.o
	$(CC) -o random_engine random_engine.o $(LIBS)

clean:	
	rm -f $(EXAMPLES) *.o

test: all
	@echo Test running random_engine
	./random_engine

