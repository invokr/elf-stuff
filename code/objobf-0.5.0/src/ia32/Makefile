

ifndef CC
CC=gcc
endif

ifndef DFLAGS
DFLAGS=-g -ggdb #-pg -a
endif
DFLAGS+=$(FLAGS_DUPE_DEBUG)

ifndef CFLAGS
CFLAGS=-pedantic -Wall
endif
CFLAGS+=$(DFLAGS)
CFLAGS+=-I. -I../common -I../elf
CFLAGS+=$(FLAGS_OPTIMIZE)

OBJS=../common/common.o ia32-debug.o ia32-function.o ../elf/elf_reloc.o
LOBJS=ia32-codeflow.o ia32-debug.o ia32-decode.o ia32-encode.o ia32-trace.o \
	ia32-function.o ia32-dataflow.o ia32_opcodes.o
LIBS=-L../elf -lxelf

all:	opcode-table libia32 ia32-decode ia32-trace test $(OBJS)

clean:
	rm -f *.o ia32-decode ia32-trace test libia32.a
	rm -f ia32_opcodes.c ia32_opcodes.h

opcode-table:	ia32-decode.c
	./build-opcode-list.sh

libia32:	opcode-table $(LOBJS)
	ar rc libia32.a $(LOBJS)

ia32_opcodes.o:	opcode-table
	gcc -c -o ia32_opcodes.o ia32_opcodes.c $(CFLAGS)

ia32-trace:	ia32-trace.c ia32-decode.o ia32-function.o
	$(CC) -o ia32-trace $(CFLAGS) -DTESTING $(OBJS) \
		ia32-trace.c ia32-decode.o ia32-codeflow.o ia32-dataflow.o \
		ia32_opcodes.o \
		$(LIBS)

ia32-decode:	ia32-decode.c libia32
	$(CC) -o ia32-decode $(CFLAGS) -DTESTING ia32-decode.c libia32.a \
		$(LIBS)

test:	test.asm
	nasm -f bin -o test test.asm


