#!/bin/sh

function cwarn() {
    COLOR='\033[01;31m'
    RESET='\033[00;00m'
    MESSAGE=${@:-"${RESET}Error: No message passed"}
    echo -e "${COLOR}${MESSAGE}${RESET}"
}

function cinfo() {
    COLOR='\033[01;32m'
    RESET='\033[00;00m'
    MESSAGE=${@:-"${RESET}Error: No message passed"}
    echo -e "${COLOR}${MESSAGE}${RESET}"
}

echo $0
cinfo "cleaning"
make clean
cinfo "building"
make | grep "error"
cinfo "creating filesystem"
./gen_filesys.sh | grep "error"

cinfo "running tests"

make check

cinfo "run done"
