PROGNAME=s84370
SSLDIR=~/src/openssl-3.0.0
SSLLIBFLAGS=-lcrypto
SSLFLAGS=-L $(SSLDIR) -isystem $(SSLDIR)/include

all:
	cc -g -Wall $(SSLFLAGS) $(PROGNAME).c $(SSLLIBFLAGS) -o $(PROGNAME)

run:
	@LD_LIBRARY_PATH=$(SSLDIR) ./$(PROGNAME)
