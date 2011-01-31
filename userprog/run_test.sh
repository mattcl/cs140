#!/bin/sh
echo $0
echo cleaning
make clean
echo building
make
echo creating filesystem
./gen_filesys.sh insult test1
echo done
