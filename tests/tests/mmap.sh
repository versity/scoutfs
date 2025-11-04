#
# test mmap() and normal read/write consistency between different nodes
#

t_require_commands mmap_stress mmap_validate scoutfs xfs_io

echo "== mmap_stress"
mmap_stress 8192 30 "$T_D0/mmap_stress" "$T_D1/mmap_stress" "$T_D2/mmap_stress" "$T_D3/mmap_stress" "$T_D4/mmap_stress" | sed 's/:.*//g' | sort

echo "== basic mmap/read/write consistency checks"
mmap_validate 256 1000 "$T_D0/mmap_val1" "$T_D1/mmap_val1"
mmap_validate 8192 1000 "$T_D0/mmap_val2" "$T_D1/mmap_val2"
mmap_validate 88400 1000 "$T_D0/mmap_val3" "$T_D1/mmap_val3"

echo "== mmap read from offline extent"
F="$T_D0/mmap-offline"
touch "$F"
xfs_io -c "pwrite -S 0xEA 0 8192" "$F" > /dev/null
cp "$F" "${F}-stage"
vers=$(scoutfs stat -s data_version "$F")
scoutfs release "$F" -V "$vers" -o 0 -l 8192
scoutfs get-fiemap -L "$F"
xfs_io -c "mmap -rwx 0 8192" \
	-c "mread -v 512 16" "$F" &
sleep 1
# should be 1 - data waiting
jobs | wc -l
scoutfs stage "${F}-stage" "$F" -V "$vers" -o 0 -l 8192
# xfs_io thread <here> will output 16 bytes of read data
sleep 1
# should be 0 - no more waiting jobs, xfs_io should have exited
jobs | wc -l
scoutfs get-fiemap -L "$F"

echo "== mmap write to an offline extent"
# reuse the same file
scoutfs release "$F" -V "$vers" -o 0 -l 8192
scoutfs get-fiemap -L "$F"
xfs_io -c "mmap -rwx 0 8192" \
	-c "mwrite -S 0x11 528 16" "$F" &
sleep 1
# should be 1 job waiting
jobs | wc -l
scoutfs stage "${F}-stage" "$F" -V "$vers" -o 0 -l 8192
# no output here from write
sleep 1
# should be 0 - no more waiting jobs, xfs_io should have exited
jobs | wc -l
scoutfs get-fiemap -L "$F"
# read back contents to assure write changed the file
dd status=none if="$F" bs=1 count=48 skip=512 | hexdump -C

echo "== done"
t_pass
