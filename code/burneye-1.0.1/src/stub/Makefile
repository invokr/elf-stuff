
ifeq ($(debug),on)
CFLAGS += -g -ggdb
DFLAGS += -DDEBUG -DVDEBUG
ENTRY_POINT = be_entry
else
ENTRY_POINT = glent
endif
DFLAGS += -DIN_STUB

CFLAGS += -Wall -fconserve-space -Os -fno-builtin $(DFLAGS)

OBJS =	callgate.o cgate.o helper.o init.o stub.o snprintf.o \
	cipher-glfsr.o cipher-glfsr-c.o cipher-rc4.o cipher-sha1.o \
	rs.o fingerprint.o


# basic targets
#
# all = generic stub-only target
# rel = target when creating real stub
#

all:	buildtools unlinkstub.bin.h stub.bin.h


# clean target
#

clean:
	make -C utils clean
	rm -f *.o *.map *.bin
	rm -f utils/sstrip
	rm -f stub-bin stub-bin.lds stub-bin.h
	rm -f unlinkstub.bin unlinkstub-bin.h


# main stub target
#

stub.bin:	buildtools $(OBJS) stub.lds
	sed s/entry_point/$(ENTRY_POINT)/ < stub.lds > stub-bin.lds
	ld -Map stub.map -s -T stub-bin.lds -o stub.bin $(OBJS)
	rm -f stub-bin.lds
ifeq ($(rel),on)
	strip stub.bin
	utils/sstrip stub.bin
endif

stub.bin.h:	stub.bin
	echo "unsigned char	stub_bin[] =" > stub-bin.h
	utils/hdump < stub.bin >> stub-bin.h
ifeq ($(debug),on)
	echo "#define BE_LAYER0_START 0x0" >> stub-bin.h
	echo "#define BE_LAYER0_FILESTART 0x0" >> stub-bin.h
	echo "#define BE_LAYER0_SIZE 0x0" >> stub-bin.h
	echo "#define BE_LAYER0_CONT 0x0" >> stub-bin.h
else
	egrep "\.text.+0x.+0x.+cipher-glfsr.o" stub.map | \
		awk '{ printf ("#define BE_LAYER0_START %s\n", $$2); }' \
		>> stub-bin.h
	readelf -l stub.bin | grep LOAD | head -1 | \
		awk '{ printf ("#define BE_LAYER0_FILESTART (BE_LAYER0_START - %s)\n", $$3); }' \
		>> stub-bin.h
	egrep "\.text.+0x.+0x.+cipher-glfsr.o" stub.map | \
		awk '{ printf ("#define BE_LAYER0_SIZE %s\n", $$3); }' \
		>> stub-bin.h
	egrep "be_entry" stub.map | \
		awk '{ printf ("#define BE_LAYER0_CONT %s\n", $$1); }' \
		>> stub-bin.h
endif
#	utils/sstrip stub.bin

unlinkstub.bin.h:	unlinkstub.bin
	echo "unsigned char	ul_stub[] =" > unlinkstub-bin.h
	utils/hdump < unlinkstub.bin >> unlinkstub-bin.h

unlinkstub.bin:	unlink_stub.asm
	nasm -f bin -o unlinkstub.bin unlink_stub.asm


# tool target
#

buildtools:
	make -C utils all

sstrip:	utils/sstrip.c
	$(CC) -o utils/sstrip -O2 -Wall utils/sstrip.c

hdump:	utils/hdump.c
	$(CC) -o utils/hdump -O2 -Wall utils/hdump.c


# sub object-targets
#
cipher-glfsr-c.o:	cipher-glfsr.asm
	nasm -DCONSERVE_SPACE -f elf -o cipher-glfsr-c.o cipher-glfsr.asm

cipher-glfsr.o:	cipher-glfsr.asm
	nasm $(DFLAGS) -f elf -o cipher-glfsr.o cipher-glfsr.asm

init.o:	init.asm
	nasm $(DFLAGS) -f elf -o init.o init.asm

callgate.o:	callgate.asm
	nasm -f elf -o callgate.o callgate.asm

lde32.o:	lde32.asm
	nasm -f elf -o lde32.o lde32.asm

