#
# make sure we clean up orphaned inodes
#

t_require_commands sleep touch sync stat handle_cat kill rm
t_require_mounts 2

#
# usually bash prints an annoying output message when jobs
# are killed.  We can avoid that by redirecting stderr for
# the bash process when it reaps the jobs that are killed.
#
silent_kill() {
	exec {ERR}>&2 2>/dev/null
	kill "$@"
	wait "$@"
	exec 2>&$ERR {ERR}>&-
}

#
# We don't have a great way to test that inode items still exist.   We
# don't prevent opening handles with nlink 0 today, so we'll use that.
# This would have to change to some other method.
#
inode_exists()
{
	local ino="$1"

	scoutfs get-allocated-inos -i "$ino" -s -p "$T_M0" > $T_TMP.inos.log 2>&1
	test "$?" == 0 -a "$(head -1 $T_TMP.inos.log)" == "$ino"
}

echo "== test our inode existance function"
path="$T_D0/file"
touch "$path"
ino=$(stat -c "%i" "$path")
inode_exists $ino || echo "$ino didn't exist"

echo "== unlinked and opened inodes still exist"
sleep 1000000 < "$path" &
pid="$!"
rm -f "$path"
inode_exists $ino || echo "$ino didn't exist"

echo "== orphan from failed evict deletion is picked up"
# pending kill signal stops evict from getting locks and deleting
silent_kill $pid
sleep 55
inode_exists $ino && echo "$ino still exists"

echo "== orphaned inos in all mounts all deleted"
pids=""
inos=""
for nr in $(t_fs_nrs); do
	eval path="\$T_D${nr}/file-$nr"
	touch "$path"
	inos="$inos $(stat -c %i $path)"
	sleep 1000000 < "$path" &
	pids="$pids $!"
	rm -f "$path"
done
sync
silent_kill $pids
for nr in $(t_fs_nrs); do
	t_force_umount $nr
done
t_mount_all
# wait for all fence requests to complete
while test -d $(echo /sys/fs/scoutfs/*/fence/* | cut -d " " -f 1); do
	sleep .5
done
# wait for orphan scans to run
sleep 55
for ino in $inos; do
	inode_exists $ino && echo "$ino still exists"
done

t_pass
