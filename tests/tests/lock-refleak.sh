#
# make sure we don't leak lock refs
#
# We've had bugs where we leak lock references.  We perform a bunch
# of operations and if they're leaking we should see user counts
# related to the number of iterations.  The test assumes that the
# system is relatively idle and that they're won't be significant
# other users of the locks.
#

t_require_commands mkdir touch stat setfattr getfattr cp mv rm cat awk

DIR="$T_D0/dir"

echo "== make test dir"
mkdir "$DIR"

echo "== do enough stuff to make lock leaks visible"
for i in $(seq 1 20); do
	t_quiet touch "$DIR/file"
	t_quiet stat "$DIR/file"
	t_quiet setfattr -n "user.name" -v "$i" "$DIR/file"
	t_quiet getfattr --absolute-names -d "$DIR/file"
	echo "pants" >> "$DIR/file"
	t_quiet cp "$DIR/file" "$DIR/copied"
	t_quiet mv "$DIR/copied" "$DIR/moved"
	t_quiet truncate -s 0 "$DIR/moved"
	t_quiet rm -f "$DIR/moved"
done

# start 2.2.0.0.0.0 end 2.2.255.18446744073709551615.18446744073709551615.255 refresh_gen 1 mode 2 waiters: rd 0 wr 0 wo 0 users: rd 0 wr 1 wo 0
# users are fields 18, 20, 22

echo "== make sure nothing has leaked"
awk '($18 > 10 || $20 > 10 || $22 > 10) {
	print $i, "might have leaked:", $0
}' < "$(t_debugfs_path)/client_locks"

t_pass
