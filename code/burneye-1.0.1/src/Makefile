
ifeq ($(debug),on)
CFLAGS += -g -ggdb
DFLAGS += -DDEBUG -DVDEBUG
MPASS += debug=on
endif

CFLAGS += -Wall $(DFLAGS)

CC=gcc
OBJS =	common.o \
	cipher-glfsr.o cipher-rc4.o cipher-sha1.o fingerprint.o rs.o

# basic targets
#

all:	debug fingerprint stub/stub.bin burneye.c $(OBJS)
	$(CC) $(CFLAGS) -o burneye burneye.c $(OBJS)

harddist:	clean stub/stub.bin burneye.c $(OBJS)
	diet $(CC) -DSTANDALONE $(CFLAGS) -o fingerprint -static \
		stub/fingerprint.c rs.o cipher-sha1.o
	strip fingerprint
	stub/utils/sstrip fingerprint

	diet $(CC) $(CFLAGS) -o burneye burneye.c -static $(OBJS)
	strip burneye
	stub/utils/sstrip burneye

	./burneye fingerprint
	mv output fingerprint
	chmod 700 fingerprint
	readelf -l fingerprint

	# burneye itself should be the last binary, for that it will
	# modify itself
	./burneye -B BANNER-BURNEYE -p accept burneye
	mv output burneye
	chmod 700 burneye
	readelf -l burneye


# release=release-string should be set ;)
release:	clean harddist
	mkdir ../dist/burneye-$(release)/
	cp burneye fingerprint ../dist/burneye-$(release)/
	cp ../doc/DIST-README ../dist/burneye-$(release)/README
	chmod 600 ../dist/burneye-$(release)/README
	chmod 700 ../dist/burneye-$(release)/burneye \
		../dist/burneye-$(release)/fingerprint

# clean targets
#

clean:
	rm -f debug/memdump
	rm -f *.o burneye
	rm -f fingerprint
	rm -f rstest
	rm -f output date.eye
	make -C stub clean


# debug targets
#

debug:	debug/memdump

debug/memdump:	debug/memdump.c
	$(CC) $(CFLAGS) -o debug/memdump debug/memdump.c

regress:	regress-clean all date.eye regress.sh
	./regress.sh

regress-clean:	clean
	rm -f date.eye
	rm -f date.*.0x* date.*.regs

date.eye:	date all
	./burneye date
	mv output date.eye
	chmod 700 date.eye


# sub object-targets
#

cipher-glfsr.o:	stub/cipher-glfsr.asm
	nasm $(DFLAGS) -f elf -o cipher-glfsr.o stub/cipher-glfsr.asm

cipher-rc4.o:	stub/cipher-rc4.c
	$(CC) $(CFLAGS) -c stub/cipher-rc4.c -o cipher-rc4.o

cipher-sha1.o:	stub/cipher-sha1.c
	$(CC) $(CFLAGS) -c stub/cipher-sha1.c -o cipher-sha1.o

fingerprint.o:	stub/fingerprint.c
	$(CC) $(CFLAGS) -c stub/fingerprint.c -o fingerprint.o

rs.o:	stub/rs.c
	$(CC) $(CFLAGS) -c stub/rs.c -o rs.o

stub/stub.bin:
	make -C stub rel=on $(MPASS) clean all


# testing tool targets
#

fingerprint:	stub/fingerprint.c cipher-sha1.o rs.o
	$(CC) -DSTANDALONE $(CFLAGS) -o fingerprint \
		stub/fingerprint.c rs.o cipher-sha1.o

rstest:	rstest.c rs.o
	$(CC) $(CFLAGS) -o rstest rstest.c rs.o

