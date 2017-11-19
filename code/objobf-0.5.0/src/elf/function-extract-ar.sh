#!/bin/sh

if [ $# -lt 1 ]; then
	echo "usage: $0 <library-object.a> [options]"
	echo
	exit
fi;

rm -fR tmp-lib
mkdir tmp-lib
cp $1 tmp-lib/
cd tmp-lib
ar x *.a
ld -q -r -o ../tmp-ar-lib.final.o *.o
cd ..
rm -fR tmp-lib
shift
./function-extract tmp-ar-lib.final.o $@
rm tmp-ar-lib.final.o debug.dot
#rm debug.ps

