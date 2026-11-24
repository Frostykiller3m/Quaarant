#!/bin/sh
uname -a
id
cat /etc/os-release
nproc 2>/dev/null || grep -c processor /proc/cpuinfo
df -h . | tail -1
ls /proc/self >/dev/null
awk 'NR<=3' /etc/passwd
