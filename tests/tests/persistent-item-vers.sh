#
# make sure we increment item vers from persistent items
#
# Make sure that new locks are given a write_version that is greater
# than all existing items so that new items with greater versions are
# preferred over old versions with lesser versions.
#
# We create an inode in a mount that has been granted multiple locks,
# which could lead to a greater version.  We then modify the item very
# early in a mount so that it's lock could have a lesser version.
#
# This was all written to test a bug where the write_version was
# statically initialized as the module was inserted.
#

t_require_commands mkdir createmany touch stat sleep diff

echo "== advance lock version by creating unrelated files"
mkdir "$T_D0/a"
createmany -o "$T_D0/a/file-" 10240 2>&1 > /dev/null
mkdir "$T_D0/b"
createmany -o "$T_D0/b/file-" 10240 2>&1 > /dev/null

echo "== create before file version"
touch "$T_D0/file"
stat "$T_D0/file" | grep Modify: > "$T_TMP.before"

# remount, possibly wiping the lock server's write_version
t_reinsert_remount_all

echo "== verify before version, touch after version"
stat "$T_D0/file" | grep Modify: > "$T_TMP.b"
diff -u "$T_TMP.before" "$T_TMP.b"
sleep 1
touch "$T_D0/file"
stat "$T_D0/file" | grep Modify: > "$T_TMP.after"

# remount and make sure we got the newest version
t_remount_all

echo "== verify after version"
stat "$T_D0/file" | grep Modify: > "$T_TMP.a"
diff -u "$T_TMP.after" "$T_TMP.a"

t_pass
