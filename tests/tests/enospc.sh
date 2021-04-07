#
# Create a lot of files with large names.  In the past this caught bugs
# in the btree code as it stored manifest entries with large keys that
# stored directory entry names.  Now keys are a small fixed size so this
# has less of an effect.
#

t_require_commands createmany scoutfs mount rm

# create filesystem on extra devs since we want meta dev small enough to enospc
# note: using different port nums.

scoutfs mkfs -f -Q 0,127.0.0.1,45000 -m 4G $T_EX_META_DEV $T_EX_DATA_DEV >/dev/null

# mount somewhere different than main mounts
dir="/mnt/test_ex.0"

mkdir -p "$dir"
mount -t scoutfs -o metadev_path=$T_EX_META_DEV,quorum_slot_nr=0 $T_EX_DATA_DEV $dir

DIRS="0 1 2"
COUNT=100000
for i in $DIRS; do
	d="$dir/$i"
	mkdir -p "$d"
	echo "dir $d"
	# Use an absurdly long file name to blow the dirent key sizes out
	./src/createmany -o $d/file_$(printf "a%.0s" {1..195})_$i $COUNT -s 0 \
		>> $T_TMP.log
	echo $?
done

# Should now be out of space.
# Delete some stuff to get us back into good territory

rm -rf $dir/0/ $dir/1/ $dir/2/

# Try really hard to get a new transaction here, since we need the SPACE_LOW
# flag to no longer be set.
sync
sync
sync
blockdev --flushbufs $T_EX_META_DEV
blockdev --flushbufs $T_EX_DATA_DEV
sync
sync
sync

# should now be able to write more stuff
d="$dir/new"
mkdir -p $d
./src/createmany -o $d/file_$(printf "a%.0s" {1..195}) $COUNT \
		 >> $T_TMP.log
echo $?

t_pass
