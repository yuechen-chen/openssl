#
# To run the demos when linked with a shared library (default):
#
#    LD_LIBRARY_PATH=../.. ./EVP_MD_demo

CFLAGS = -I../../include -g
LDFLAGS = -L../..
LDLIBS = -lcrypto

all: EVP_ECDSA_demo

%.o: %.c
	$(CC) $(CFLAGS) -c $<

EVP_ECDSA_demo: EVP_ECDSA_demo.o

test: ;

clean:
	$(RM) *.o EVP_ECDSA_demo
