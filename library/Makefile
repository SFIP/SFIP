all: filter.o cJSON.o sandboxing.o

CFLAGS ?= -Wno-unused-value
LDFLAGS=

filter.o: filter.c
	clang filter.c -c -O ${CFLAGS}

cJSON.o: cJSON.c
	clang -c cJSON.c -fPIC $(CFLAGS)

sandboxing.o: sandboxing.c
	clang sandboxing.c -c -O ${CFLAGS}

clean:
	rm *.o -f
