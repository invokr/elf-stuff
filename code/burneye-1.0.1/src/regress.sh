#!/bin/sh

rm -f date.*.0x* date.*.0x*.hex date.*.0x*.diff date.*.regs

# $entry = ld-linux.so.2 entry point
entry=`objdump -f /lib/ld-linux.so.2 | \
	grep "start address" | cut -d ' ' -f3 | \
	sed "s/0x0000/0x4000/g"`

debug/memdump $entry ./date.eye
debug/memdump $entry ./date.upx

clear

for file in date.eye.0x*
do
	upx_file=`echo $file | sed s/eye/upx/`
	if [ -f $upx_file ]; then
		if cmp $file $upx_file
		then
			echo $file, $upx_file are identical
		else
			echo $file, $upx_file are different, analyzing

			hexdump < $file > $file.hex
			hexdump < $upx_file > $upx_file.hex
		fi
	else
		echo "$upx_file does not exist."
	fi
done

if ls date.eye.0x*.hex >/dev/null 2>/dev/null
then
for file in date.eye.0x*.hex
do
	upx_file=`echo $file | sed s/eye/upx/`
	linecount=`diff -u $file $upx_file | wc | awk '{ print $1 }'`
	if [ $linecount -gt 20 ]
	then
		echo "$file, $upx_file, more than 20 lines different"
		echo "   dumping to $file.diff"
		diff -u $file $upx_file > $file.diff
	else
		echo "$file, $upx_file, differences:"
		diff -u $file $upx_file > $file.diff
	fi
done
fi

if cmp date.eye.regs date.upx.regs
then
	echo "registers are identical"
else
	echo "registers are different (first eye, then upx):"
	diff -C 0 date.eye.regs date.upx.regs | grep "^!"
fi

