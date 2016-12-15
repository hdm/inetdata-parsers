#!/bin/bash

src=$1
mem=$(echo `free -g | grep ^Mem | awk '{print $2}'` / 8.0 | bc)G
tmp=${HOME}
thr=`nproc`
base=`basename $1`
out=`echo $base | cut -f 1 -d .`
export LC_ALL=C

time (
	nice pigz -dc ${src} | \
	head -n 10000000 | \
	nice inetdata-csvsplit -m 8 -t ${tmp} ${out}
)

# Generate a forward-lookup mtbl
time (nice pigz -dc ${out}-names.gz | nice inetdata-dns2mtbl -m 8 -t ${tmp} ${out}.mtbl)

# Generate an inverse-lookup mtbl
time (nice pigz -dc ${out}-names-inverse.gz | nice inetdata-dns2mtbl -m 8 -t ${tmp} ${out}-inverse.mtbl)
