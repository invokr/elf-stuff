#!/bin/sh

cat > ia32_opcodes.h << __EOF__
/* ia32_opcodes.h - automatically generated numeric opcode table
 *
 * WARNING: this file will have to be regenerated when ia32-decode.c is changed
 */

#ifndef	IA32_OPCODES_H
#define	IA32_OPCODES_H

__EOF__

egrep -n "{ IA32_OP" ia32-decode.c | \
	awk '{ print $1 $3 $4 }' | \
	sort -t '(' +1 | \
	uniq -t ':' -f 1 | \
	sed 's/\(.*\)\:IA32_OP(\(.*\)),/#define IA32_OP_\2 \1/g' >> ia32_opcodes.h

cat >> ia32_opcodes.h << __EOF__

#endif

__EOF__

cat > ia32_opcodes.c << __EOF__
/* ia32_opcodes.c - automatically generated numeric opcode table
 *
 * WARNING: this file will have to be regenerated when ia32-decode.c is changed
 */

#include <ia32_opcodes.h>

unsigned int ia32_opnum_table[] = {
__EOF__

cat ia32_opcodes.h | \
	grep "^#define IA32_OP_" | \
	awk '{ print $2 }' | \
	sed 's/\(.*\)/\t\1, /g' >> ia32_opcodes.c

cat >> ia32_opcodes.c << __EOF__
	0,
};

__EOF__

cat ia32_opcodes.c | \
	grep "IA32_OP_" | \
	wc -l | \
	awk '{ print $1 }' | \
	sed 's/\(.*\)/#define IA32_OPNUM_COUNT \1/g' >> ia32_opcodes.h
echo >> ia32_opcodes.h

