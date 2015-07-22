all: getting_started  random_bytes  random_engine gcm

getting_started: force
	make -C getting_started

random_bytes: force
	make -C random_bytes

random_engine: force
	make -C random_engine

gcm: force
	make -C gcm

clean:
	make -C getting_started clean
	make -C random_bytes clean
	make -C random_engine clean
	make -C gcm clean

test:
	make -C getting_started test
	make -C random_bytes test
	make -C random_engine test
	make -C gcm test

force:

