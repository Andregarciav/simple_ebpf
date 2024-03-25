#!/bin/bash
# if [ $# -ne 2 ]; then
#    echo "Wrong number of arguments." 
#    exit 1
# fi

if [ "$(id -u)" != "0" ]; then
    echo "Please, run this script as root"
    exit 1
fi

item=$1

case "$item" in
    "load")
        "$(ip -force link set eno1 xdp obj src/kernel/dpi.o sec xdp_dpi)"
    ;;
    "off")
        "$(ip link set dev eno1 xdp off)"
    ;;
    *)
        echo "./prog [load/off]"
    ;;
esac