#!/bin/bash
make clean
make
sudo insmod proj2.ko int_str="1,2,3,4,5"
# cat /proc/proj2
sudo rmmod proj2
sudo dmesg | tail -n 7
