#
# test that the data prealloc options behave as expected.  We write to
# two files a block at a time so that a single file doesn't naturally
# merge adjacent consecutive allocations.  (we don't have multiple
# allocation cursors)
#
t_require_commands scoutfs stat dd touch truncate

write_block()
{
	local file="$1"
	local blk="$2"

	dd if=/dev/zero of="$file" bs=4096 seek=$blk count=1 conv=notrunc status=none
	echo "wrote blk $blk"
}

write_forwards()
{
	local prefix="$1"
	local nr="$2"
	local blk

	touch "$prefix"-{1,2}
	truncate -s 0 "$prefix"-{1,2}

	for blk in $(seq 0 1 $((nr - 1))); do
		dd if=/dev/zero of="$prefix"-1 bs=4096 seek=$blk count=1 conv=notrunc status=none
		dd if=/dev/zero of="$prefix"-2 bs=4096 seek=$blk count=1 conv=notrunc status=none
	done
}

write_backwards()
{
	local prefix="$1"
	local nr="$2"
	local blk

	touch "$prefix"-{1,2}
	truncate -s 0 "$prefix"-{1,2}

	for blk in $(seq $((nr - 1)) -1 0); do
		dd if=/dev/zero of="$prefix"-1 bs=4096 seek=$blk count=1 conv=notrunc status=none
		dd if=/dev/zero of="$prefix"-2 bs=4096 seek=$blk count=1 conv=notrunc status=none
	done
}

release_files() {
	local prefix="$1"
	local size=$(($2 * 4096))
	local vers
	local f

	for f in "$prefix"*; do
		size=$(stat -c "%s" "$f")
		vers=$(scoutfs stat -s data_version "$f")
		scoutfs release "$f" -V "$vers" -o 0 -l $size
	done
}

stage_files() {
	local prefix="$1"
	local nr="$2"
	local vers
	local f

	for blk in $(seq 0 1 $((nr - 1))); do
		for f in "$prefix"*; do
			vers=$(scoutfs stat -s data_version "$f")
			scoutfs stage /dev/zero "$f" -V "$vers" -o $((blk * 4096)) -l 4096
		done
	done
}

print_extents_found()
{
	local prefix="$1"

	for f in "$prefix"-*; do
		echo "$f: $(scoutfs get-fiemap "$f" | tail -n 1)" | t_filter_fs
	done
}

t_save_all_sysfs_mount_options data_prealloc_blocks
t_save_all_sysfs_mount_options data_prealloc_contig_only
restore_options()
{
	t_restore_all_sysfs_mount_options data_prealloc_blocks
	t_restore_all_sysfs_mount_options data_prealloc_contig_only
}
trap restore_options EXIT

prefix="$T_D0/file"

echo "== initial writes smaller than prealloc grow to prealloc size"
t_set_sysfs_mount_option 0 data_prealloc_blocks 32
t_set_sysfs_mount_option 0 data_prealloc_contig_only 1
write_forwards $prefix 64
print_extents_found $prefix

echo "== larger files get full prealloc extents"
t_set_sysfs_mount_option 0 data_prealloc_blocks 32
t_set_sysfs_mount_option 0 data_prealloc_contig_only 1
write_forwards $prefix 128
print_extents_found $prefix

echo "== non-streaming writes with contig have per-block extents"
t_set_sysfs_mount_option 0 data_prealloc_blocks 32
t_set_sysfs_mount_option 0 data_prealloc_contig_only 1
write_backwards $prefix 32
print_extents_found $prefix

echo "== any writes to region prealloc get full extents"
t_set_sysfs_mount_option 0 data_prealloc_blocks 16
t_set_sysfs_mount_option 0 data_prealloc_contig_only 0
write_forwards $prefix 64
print_extents_found $prefix
write_backwards $prefix 64
print_extents_found $prefix

echo "== streaming offline writes get full extents either way"
t_set_sysfs_mount_option 0 data_prealloc_blocks 16
t_set_sysfs_mount_option 0 data_prealloc_contig_only 1
write_forwards $prefix 64
release_files $prefix 64
stage_files $prefix 64
print_extents_found $prefix
t_set_sysfs_mount_option 0 data_prealloc_contig_only 0
release_files $prefix 64
stage_files $prefix 64
print_extents_found $prefix

echo "== goofy preallocation amounts work"
t_set_sysfs_mount_option 0 data_prealloc_blocks 7
t_set_sysfs_mount_option 0 data_prealloc_contig_only 1
write_forwards $prefix 14
print_extents_found $prefix
t_set_sysfs_mount_option 0 data_prealloc_blocks 13
t_set_sysfs_mount_option 0 data_prealloc_contig_only 0
write_forwards $prefix 53
print_extents_found $prefix
t_set_sysfs_mount_option 0 data_prealloc_blocks 1
t_set_sysfs_mount_option 0 data_prealloc_contig_only 0
write_forwards $prefix 3
print_extents_found $prefix

#
# prepare aligned regions of 8 blocks that we'll write into.
# We'll right into the first, last, and middle block of each
# region which was prepared with no existing extents, one at
# the start, and one at the end.
#
# Let's keep this last because it creates a ton of output to read
# through.  The correct output is tied to preallocation strategy so it
# has to be verified each time we change preallocation.
#
echo "== block writes into region allocs hole" 
t_set_sysfs_mount_option 0 data_prealloc_blocks 8
t_set_sysfs_mount_option 0 data_prealloc_contig_only 1
touch "$prefix"
truncate -s 0 "$prefix"

# write initial blocks in regions
base=0
for sides in 0 1 2 3; do
	for i in 0 1 2; do
                case "$sides" in
			# none
			0) ;;
			# left
			1) write_block $prefix $((base + 0)) ;;
			# right
			2) write_block $prefix $((base + 7)) ;;
			# both
			3) write_block $prefix $((base + 0)) 
			   write_block $prefix $((base + 7)) ;;
		esac
		((base+=8))
	done
done

echo before:
scoutfs get-fiemap "$prefix" | tr -s ',' '\t' | \
	awk '($1 != "entries:") {
		unwritten = (substr($7, 2, 1) == "U") ? "unwritten" : "";
		eof = (substr($7, 3, 1) == "L") ? "eof" : "";
		print $3 ".. " $5 ": " unwritten eof;
		};'

# now write into the first, middle, and last empty block of each
t_set_sysfs_mount_option 0 data_prealloc_contig_only 0
base=0
for sides in 0 1 2 3; do
	for i in 0 1 2; do
		echo "writing into existing $sides at pos $i"
		case "$sides" in
			# none
			0) left=$base; right=$((base + 7));;
			# left
			1) left=$((base + 1)); right=$((base + 7));;
			# right
			2) left=$((base)); right=$((base + 6));;
			# both
			3) left=$((base + 1)); right=$((base + 6));;
		esac
		case "$i" in
			# start
			0) write_block $prefix $left ;;
			# end
			1) write_block $prefix $right ;;
			# mid (both has 6 blocks internally)
			2) write_block $prefix $((left + 3)) ;;
		esac
		scoutfs get-fiemap "$prefix" | tr -s ',' '\t' | \
			awk '($1 != "entries:") {
				unwritten = (substr($7, 2, 1) == "U") ? "unwritten" : "";
				eof = (substr($7, 3, 1) == "L") ? "eof" : "";
				print $3 ".. " $5 ": " unwritten eof;
				};'
		((base+=8))
	done
done

t_pass
