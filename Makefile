CC = gcc
CFLAGS = -static -Wall -w
DEPS = elf.o exec.o
LOADERS = apager dpager hpager
LOADER_CFLAGS = -T loader.ld -Wl,--no-relax

all: release

release: $(LOADERS)
	make -C tests
debug: $(LOADERS)
	make -C tests

release: CFLAGS += -O2
debug: CFLAGS += -O0 -DDEBUG -g

$(DEPS): %.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

$(LOADERS): % : %.c $(DEPS)
	$(CC) $(CFLAGS) $(LOADER_CFLAGS) -o $@ $^

clean:
	rm -f *.o $(LOADERS)
	cd ./tests; make clean; cd ..