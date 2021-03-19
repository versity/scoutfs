#
# test deleting an inode once all its links and references are gone.
#

t_require_commands cat scoutfs
t_require_mounts 2

FILE="$T_D0/file"

check_ino_index() {
	local ino="$1"
	local dseq="$2"
	local mnt="$3"

	t_sync_seq_index

	scoutfs walk-inodes -p "$mnt" -- data_seq $dseq $(($dseq + 1)) |
		awk 'BEGIN { not = "not " }
		     ($4 == '$ino') { not = ""; exit; }
		     END { print "ino " not "found in dseq index" }'
}

echo "== basic unlink deletes"
echo "contents" > "$FILE"
ino=$(stat -c "%i" "$FILE")
dseq=$(scoutfs stat -s data_seq "$FILE")
check_ino_index "$ino" "$dseq" "$T_M0"
rm -f "$FILE"
check_ino_index "$ino" "$dseq" "$T_M0"

echo "== local open-unlink waits for close to delete"
echo "contents" > "$FILE"
ino=$(stat -c "%i" "$FILE")
dseq=$(scoutfs stat -s data_seq "$FILE")
exec {FD}<"$FILE"  # open unused fd, assign to FD
rm -f "$FILE"
echo "contents after rm: $(cat <&$FD)"
check_ino_index "$ino" "$dseq" "$T_M0"
exec {FD}>&-  # close
check_ino_index "$ino" "$dseq" "$T_M0"

echo "== multiple local opens are protected"
echo "contents" > "$FILE"
ino=$(stat -c "%i" "$FILE")
dseq=$(scoutfs stat -s data_seq "$FILE")
exec {FD1}<"$FILE"
exec {FD2}<"$FILE"
rm -f "$FILE"
echo "contents after rm 1: $(cat <&$FD1)"
echo "contents after rm 2: $(cat <&$FD2)"
check_ino_index "$ino" "$dseq" "$T_M0"
exec {FD1}>&-  # close
exec {FD2}>&-  # close
check_ino_index "$ino" "$dseq" "$T_M0"

echo "== remote unopened unlink deletes"
echo "contents" > "$T_D0/file"
ino=$(stat -c "%i" "$T_D0/file")
dseq=$(scoutfs stat -s data_seq "$T_D0/file")
rm -f "$T_D1/file"
check_ino_index "$ino" "$dseq" "$T_M0"
check_ino_index "$ino" "$dseq" "$T_M1"

echo "== unlink wait for open on other mount"
echo "contents" > "$T_D0/file"
ino=$(stat -c "%i" "$T_D0/file")
dseq=$(scoutfs stat -s data_seq "$T_D0/file")
exec {FD}<"$T_D0/file"
rm -f "$T_D1/file"
echo "mount 0 contents after mount 1 rm: $(cat <&$FD)"
check_ino_index "$ino" "$dseq" "$T_M0"
check_ino_index "$ino" "$dseq" "$T_M1"
exec {FD}>&-  # close
# we know that revalidating will unhash the remote dentry
stat "$T_D0/file" 2>&1 | t_filter_fs
check_ino_index "$ino" "$dseq" "$T_M0"
check_ino_index "$ino" "$dseq" "$T_M1"

echo "== lots of deletions use one open map"
mkdir "$T_D0/dir"
touch "$T_D0/dir"/files-{1..5}
rm -f "$T_D0/dir"/files-*
rmdir "$T_D0/dir"

echo "== open files survive remote scanning orphans"
echo "contents" > "$T_D0/file"
ino=$(stat -c "%i" "$T_D0/file")
dseq=$(scoutfs stat -s data_seq "$T_D0/file")
exec {FD}<"$T_D0/file"
rm -f "$T_D0/file"
t_umount 1
t_mount 1
echo "mount 0 contents after mount 1 remounted: $(cat <&$FD)"
exec {FD}>&-  # close
check_ino_index "$ino" "$dseq" "$T_M0"
check_ino_index "$ino" "$dseq" "$T_M1"

t_pass
