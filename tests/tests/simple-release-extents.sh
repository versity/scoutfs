#
# Test that releasing extents creates offline extents.
#

t_require_commands xfs_io filefrag scoutfs mknod

# this test wants to ignore unwritten extents
fiemap_file() {
	filefrag -v -b4096 "$1" | grep -v "unwritten"
}

create_file() {
	local file="$1"
	local size="$2"

	t_quiet xfs_io -f \
		-c "falloc 0 $size" \
		-c "pwrite 0 $size" \
		"$file"
}

# if vers is "stat" then we ask stat_more for the data_version
release_vers() {
	local file="$1"
	local vers="$2"
	local offset="$3"
	local length="$4"

	if [ "$vers" == "stat" ]; then
		vers=$(scoutfs stat -s data_version "$file")
	fi

	scoutfs release "$file" -V "$vers" -o "$offset" -l "$length"
}

FILE="$T_D0/file"
CHAR="$FILE-char"

echo "== simple whole file multi-block releasing"
create_file "$FILE" 65536
release_vers "$FILE" stat 0 64K
rm "$FILE"

echo "== release last block that straddles i_size"
create_file "$FILE" 6144
release_vers "$FILE" stat 4K 4K
rm "$FILE"

echo "== release entire file past i_size"
create_file "$FILE" 8192
release_vers "$FILE" stat 0 400K
# not deleting for the following little tests

echo "== releasing offline extents is fine"
release_vers "$FILE" stat 0 400K

echo "== 0 count is fine"
release_vers "$FILE" stat 0 0

echo "== release past i_size is fine"
release_vers "$FILE" stat 400K 4K

echo "== wrapped blocks fails"
# just under!
release_vers "$FILE" stat $vers 0xfffffffffffff000 4096
# this goes over
release_vers "$FILE" stat $vers 0xfffffffffffff000 8192

echo "== releasing non-file fails"
mknod "$CHAR" c 1 3
release_vers "$CHAR" stat 0 4K 2>&1 | t_filter_fs
rm "$CHAR"

echo "== releasing a non-scoutfs file fails"
release_vers "/dev/null" stat 0 4K

echo "== releasing bad version fails"
release_vers "$FILE" 0 0 4K

rm "$FILE"

#
# Finally every combination of releasing three single block extents
# inside a 5 block file, including repeated releases, merges offline
# extents as expected.
#
# We collapse down the resulting extent output so that the golden file
# isn't one of the biggest in the tree.  Each extent is listed as
# "(logical physical count)".   Offline extents have a physical of 0 and
# real allocations are filtered to start at physical 100.
#

echo "== verify small release merging"
for a in $(seq 0 4); do
for b in $(seq 0 4); do
for c in $(seq 0 4); do

	# start with one contiguous extent
	create_file "$FILE" $((5 * 4096))
	nr=1
	while fiemap_file "$FILE" | grep -q " extents found"; do
		rm "$FILE"
		create_file "$FILE" $((5 * 4096))

		((nr++))
		if [ $nr == 10 ]; then
			t_fail "10 tries to get a single extent?"
		fi
	done

	start=$(fiemap_file "$FILE" | \
		awk '($1 == "0:"){print substr($4, 0, length($4)- 2)}')

	release_vers "$FILE" stat $(($a * 4))K 4K
	release_vers "$FILE" stat $(($b * 4))K 4K
	release_vers "$FILE" stat $(($c * 4))K 4K

	echo -n "$a $b $c:"

	fiemap_file "$FILE" | \
		awk 'BEGIN{ORS=""}($1 == (NR - 4)":") {
			off=substr($2, 0, length($2)- 2);
			phys=substr($4, 0, length($4)- 2);
			if (phys > 100) {
				phys = phys - phys + 100 + off;
			}
			len=substr($6, 0, length($6)- 1);
			print "  (" off, phys, len ")";
		}'
	echo

	rm "$FILE"
done
done
done

t_pass
