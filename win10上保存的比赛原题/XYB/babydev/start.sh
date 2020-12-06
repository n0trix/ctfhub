#!/bin/sh

timeout 300 qemu-system-x86_64 -m 256M -kernel /home/ctf/bzImage -initrd /home/ctf/core.cpio -append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 quiet nokaslr" -cpu qemu64,+smep,+smap -nographic -monitor /dev/null
