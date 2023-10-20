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

echo "== remove files and check that blocks were freed"
before=$(free_blocks Data "$T_M0")
deleted=0
for n in $(t_fs_nrs); do
	eval dir="\$T_D${n}/dir-$n"
	path="$dir/file-$n"

	ino=$(stat -c "%i" "$path")
	((deleted+=$(stat -c '%b' "$path")))
	rm -f "$path"
	echo "waiting for ino $ino path $path to delete " >> $T_TMP.waiting 2>&1
	while t_ino_has_items $ino "$T_M0"; do sleep .5; done

	rmdir "$dir"
done
# make dirty data_freed allocator trees visible
sync
#
# make sure that free data blocks increased by at least as much as we
# deleted.  This can miss problems if our deletion didn't happen but
# some other unrelated large orphan inode was still being deleted,
# perhaps by a previous test.  If that were the case it'd be
# inconsistent and we'd see sporadic failures.
#
after=$(free_blocks Data "$T_M0")
test "$after" -ge "$((before + deleted))" || \
	t_fail "$after free data blocks after rm, less than $before + $deleted"

# XXX this is all pretty manual, would be nice to have helpers
echo "== make small meta fs"
# meta device just big enough for reserves and the metadata we'll fill
scoutfs mkfs -A -f -Q 0,127.0.0.1,53000 -m 10G "$T_EX_META_DEV" "$T_EX_DATA_DEV" > $T_TMP.mkfs.out 2>&1 || \
	t_fail "mkfs failed"
SCR="$T_TMPDIR/mnt.scratch"
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
