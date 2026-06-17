#
# Destructive: the alloc_fill_freed_list trigger claims free blocks and leaks
# them into both server_meta_freed heads in one commit, filling them near-full.
# Runs on a scratch fs; mkfs before re-use.
#
# A fixed server drains the full heads and stays live; an unfixed server wedges
# on the next commit and hangs until the harness times it out.
#

scr_counter() {
	cat "$(t_sysfs_path_from_mnt "$T_MSCR")/counters/$1"
}

echo "== make throwaway scratch fs"
t_scratch_mkfs
t_scratch_mount

echo "== stuff both server freed heads full in one commit"
old=$(scr_counter alloc_freed_fill)

echo 1 > "/sys/kernel/debug/scoutfs/$(t_ident_from_mnt "$T_MSCR")/trigger/alloc_fill_freed_list"
echo one > "$T_MSCR/one"; sync

echo "== confirm both heads were stuffed (not a no-op)"
filled=$(($(scr_counter alloc_freed_fill) - old))
test "$filled" -ge 2 && echo "both freed heads stuffed" || \
	echo "stuff was a no-op ($filled heads)"

echo "== a fixed server drains them and keeps making progress"
# an unfixed server wedges on this commit
echo two > "$T_MSCR/two"; sync
cat "$T_MSCR/one" "$T_MSCR/two"

rm -f "$T_MSCR/one" "$T_MSCR/two"; sync

echo "== cleanup scratch fs"
t_scratch_umount

t_pass
