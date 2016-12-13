#!/bin/bash

src=$1
mem=$(echo `free -g | grep ^Mem | awk '{print $2}'` / 8.0 | bc)G
tmp=${HOME}
thr=`nproc`
base=`basename $1`
out=`echo $base | cut -f 1 -d .`
export LC_ALL=C

# Sort, rollup, and resort the forward lookup CSV
time ( 
	nice pigz -dc ${src} | \
	nice sort -u -S ${mem} --parallel=${thr} -k 1 -t , -T ${tmp} --compress-program=pigz | \
	nice sonar-csvrollup | \
	nice sort -u -S ${mem} --parallel=${thr} -k 1 -t , -T ${tmp} --compress-program=pigz  | \
	nice pigz -c > ${out}.merged.gz
sleep 1
) &
dns_rollup_pid=$!

# Spawn the inverter to generated sorted and rollup inverse CSVs
time (
	nice pigz -dc ${src} | \
	nice sonar-csvinvert -m 8 -t ${tmp} ${out}-inverse
sleep 1
) &
dns_invert_pid=$!

echo "[*] Waiting on first round of conversion jobs..."
wait $dns_rollup_pid
wait $dns_invert_pid


# Generate a forward-lookup mtbl
time ( 
	nice pigz -dc ${out}.merged.gz |
	nice sonar-dns2mtbl -m 8 -t ${tmp} ${out}.mtbl
)

# Generate an inverse-lookup mtbl for each output
for i in `find -name "${out}-inverse-*.gz"`; do
	inverse_base=`basename $i`
	inverse_out=`echo $inverse_base | cut -f 1 -d .`
	time (
		nice pigz -dc ${i} |
		nice sonar-dns2mtbl -m 8 -t ${tmp} ${inverse_out}.mtbl
	)
done
