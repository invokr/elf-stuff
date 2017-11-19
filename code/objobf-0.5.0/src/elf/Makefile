
#ELF_DEBUG_PRINT=-DDEBUG

ifndef CC
CC=gcc
endif

ifndef DFLAGS
DFLAGS=-g -ggdb $(ELF_DEBUG_PRINT) #-pg -a
endif

ifndef CFLAGS
CFLAGS=-Wall
endif
CFLAGS+=-I. -I../common -I../ia32
CFLAGS+=$(DFLAGS)
CFLAGS+=$(FLAGS_OPTIMIZE)

LIBS=
OBJS=	../common/common.o elf_base.o elf_file.o elf_dump.o elf_reloc.o \
	elf_section.o elf_segment.o elf_symbol.o elf_verify.o elf_util.o
OBJS_IA32= ia32-glue.o

all:	elflib function-extract

clean:
	rm -f *.o function-extract libxelf.a

elflib:	$(OBJS) $(OBJS_IA32)
	ar rc libxelf.a $(OBJS) $(OBJS_IA32)

function-extract:	function-extract.c $(OBJS) $(OBJS_IA32)
	$(CC) $(CFLAGS) -o function-extract function-extract.c \
		../ia32/ia32-debug.c ../ia32/ia32-decode.c \
		../ia32/ia32-trace.c ../ia32/ia32-function.c \
		$(OBJS) $(OBJS_IA32) $(LIBS)

