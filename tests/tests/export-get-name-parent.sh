#
# Test operation of scoutfs_get_name and scoutfs_get_parent. We can do
# this by creating a directory, recording it's inode number then
# opening it by handle after a remount.
#

t_require_commands mkdir stat handle_cat

DIR="$T_D0/dir"

mkdir -p "$DIR"
ino=$(stat -c "%i" "$DIR")

t_umount_all
t_mount_all

t_quiet handle_cat "$T_M0" "$ino"

t_pass
