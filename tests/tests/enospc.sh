#
# test hititng enospc by filling with data or metadata and
# then recovering by removing what we filled.
#

#    Type  Size     Total   Used      Free  Use%  
#MetaData  64KB   1048576  32782   1015794     3  
#    Data   4KB  16777152      0  16777152     0  
free_blocks() {
	local md="$1"
	local mnt="$2"
	scoutfs df -p "$mnt" | awk '($1 == "'$md'") { print $5; exit }'
}

t_require_commands scoutfs stat fallocate createmany

echo "== prepare directories and files"
for n in $(t_fs_nrs); do
	eval path="\$T_D${n}/dir-$n/file-$n"
	mkdir -p $(dirname $path)
	touch $path
done
sync

echo "== fallocate until enospc"
before=$(free_blocks Data "$T_M0")
finished=0
while [ $finished != 1 ]; do
	for n in $(t_fs_nrs); do
		eval path="\$T_D${n}/dir-$n/file-$n"
		off=$(stat -c "%s" "$path")

		LC_ALL=C fallocate -o $off -l 128MiB  "$path" > $T_TMP.fallocate 2>&1
		err="$?"

		if grep -qi "no space" $T_TMP.fallocate; then
			finished=1
			break
		fi
		if [ "$err" != "0" ]; then
			t_fail "fallocate failed with $err"
		fi
	done
done

echo "== remove all the files and verify free data blocks"
for n in $(t_fs_nrs); do
	eval dir="\$T_D${n}/dir-$n"
	rm -rf "$dir"
done
sync
after=$(free_blocks Data "$T_M0")
# nothing else should be modifying data blocks
test "$before" == "$after" || \
	t_fail "$after free data blocks after rm, expected $before"

# XXX this is all pretty manual, would be nice to have helpers
echo "== make small meta fs"
# meta device just big enough for reserves and the metadata we'll fill
scoutfs mkfs -A -f -Q 0,127.0.0.1,53000 -m 10G "$T_EX_META_DEV" "$T_EX_DATA_DEV" > $T_TMP.mkfs.out 2>&1 || \
	t_fail "mkfs failed"
SCR="/mnt/scoutfs.enospc"
mkdir -p "$SCR"
mount -t scoutfs -o metadev_path=$T_EX_META_DEV,quorum_slot_nr=0 \
	"$T_EX_DATA_DEV" "$SCR"

echo "== create large xattrs until we fill up metadata"
mkdir -p "$SCR/xattrs"

for f in $(seq 1 100000); do
	file="$SCR/xattrs/file-$f"
	touch "$file"

	LC_ALL=C create_xattr_loop -c 1000 -n user.scoutfs-enospc -p "$file" -s 65535 > $T_TMP.cxl 2>&1
	err="$?"

	if grep -qi "no space" $T_TMP.cxl; then
		echo "enospc at f $f" >> $T_TMP.cxl
		break
	fi
	if [ "$err" != "0" ]; then
		t_fail "create_xattr_loop failed with $err"
	fi
done

echo "== remove files with xattrs after enospc"
rm -rf "$SCR/xattrs"

echo "== make sure we can create again"
file="$SCR/file-after"
touch $file
setfattr -n user.scoutfs-enospc -v 1 "$file"
sync
rm -f "$file"

echo "== cleanup small meta fs"
umount "$SCR"
rmdir "$SCR"

t_pass
