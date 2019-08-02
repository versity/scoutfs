#
# Test basic correctness of tracking online, offline, and st_blocks
# counts.
#

t_require_commands scoutfs dd truncate touch mkdir rm rmdir

# if vers is "stat" then we ask stat_more for the data_version
release_vers() {
	local file="$1"
	local vers="$2"
	local block="$3"
	local count="$4"

	if [ "$vers" == "stat" ]; then
		vers=$(scoutfs stat -s data_version "$file")
	fi

	scoutfs release "$file" "$vers" "$block" "$count"
}

# if vers is "stat" then we ask stat_more for the data_version
stage_vers() {
	local file="$1"
	local vers="$2"
	local offset="$3"
	local count="$4"
	local contents="$5"

	if [ "$vers" == "stat" ]; then
		vers=$(scoutfs stat -s data_version "$file")
	fi

	scoutfs stage "$file" "$vers" "$offset" "$count" "$contents"
}

echo_blocks()
{
	echo "online:" $(scoutfs stat -s online_blocks "$1")
	echo "offline:" $(scoutfs stat -s offline_blocks "$1")
	echo "st_blocks:" $(stat -c '%b' "$1")
}

FILE="$T_D0/file"
DIR="$T_D0/dir"

echo "== single block write"
dd if=/dev/zero of="$FILE" bs=4K count=1 status=none
echo_blocks "$FILE"

echo "== single block overwrite"
dd if=/dev/zero of="$FILE" bs=4K count=1 conv=notrunc status=none
echo_blocks "$FILE"

echo "== append"
dd if=/dev/zero of="$FILE" bs=4K count=1 conv=notrunc oflag=append status=none
echo_blocks "$FILE"

echo "== release"
release_vers "$FILE" stat 0 2
echo_blocks "$FILE"

echo "== duplicate release"
release_vers "$FILE" stat 0 2
echo_blocks "$FILE"

echo "== duplicate release past i_size"
release_vers "$FILE" stat 0 16
echo_blocks "$FILE"

echo "== stage"
stage_vers "$FILE" stat 0 8192 /dev/zero
echo_blocks "$FILE"

echo "== duplicate stage"
stage_vers "$FILE" stat 0 8192 /dev/zero
echo_blocks "$FILE"

echo "== larger file"
dd if=/dev/zero of="$FILE" bs=1M count=1 status=none
echo_blocks "$FILE"

echo "== partial truncate"
truncate -s 512K "$FILE"
echo_blocks "$FILE"

echo "== single sparse block"
rm -f "$FILE"
dd if=/dev/zero of="$FILE" bs=4K count=1 seek=1K status=none
echo_blocks "$FILE"

echo "== empty file"
rm -f "$FILE"
touch "$FILE"
echo_blocks "$FILE"

echo "== non-regular file"
mkdir "$DIR"
echo_blocks "$DIR"

echo "== cleanup"
rm -f "$FILE"
rmdir "$DIR"

t_pass
