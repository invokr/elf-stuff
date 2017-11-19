#!/bin/sh
vers=`uname -m`
if [ "$vers" = "x86_64" ]; then
	cp stub/linker_script/stub64.lds stub/linker_script/stub.lds
 else
	cp stub/linker_script/stub32.lds stub/linker_script/stub.lds
fi
