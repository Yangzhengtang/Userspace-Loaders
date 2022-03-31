CC = gcc
CFLAGS = -static -Wall -w -O2 -Wl,-z,norelro
TESTS = test_hello_world test_cpu_heavy test_large_array_seq test_large_array_rand test_null_ref

all: $(TESTS)

$(TESTS): % : %.c
	$(CC) $(CFLAGS) -o $@ $^
clean:
	rm -f $(TESTS)