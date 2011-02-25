#!/bin/sh
echo $0
echo creating filesys

pintos-mkdisk build/filesys.dsk --filesys-size=2 --swap-size=2
pintos -f -q

echo adding merge seq
pintos -p build/test/vm/page-merge-seq -a page-merge-seq -- -q

while [ -n "$*" ]
do
	if [ `basename $1` = $1 ]
	then
		echo putting $1 from examples dir
		pintos -p ../examples/$1 -a $1 -- -q
	else
		echo putting `basename $1` from $1
		pintos -p $1 -a `basename $1` -- -q
	fi
	shift
done

echo All Done
