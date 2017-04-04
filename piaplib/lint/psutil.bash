#!/bin/bash
ulimit -t 2
ps -elf | tr -s ' ' | cut -d\  -f 3,15 | sed -E -e 's/[\[\(]{1}[^]]+[]\)]{1}/SYSTEM/g' | sort | uniq ;
exit 0 ;

