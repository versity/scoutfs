#
# Open and unlink a directory on one node; then try to create various objects in that
# directory on another node. Those attempts should fail with ENOENT.

t_require_commands ln mkdir mv o_tmpfile_linkat rmdir scoutfs sync touch
t_require_mounts 2

mkdir "$T_D1/orphan-dir"
touch "$T_D1/rename-src"
touch "$T_D1/link-src"
touch "$T_D1/symlink-src"

# Sit in the directory that's about to be orphaned from another client
cd "$T_D1/orphan-dir"

rmdir "$T_D0/orphan-dir"

touch newfile
if [ $? -eq 0 ]; then
	echo Orphaned dir allowed a create
fi

mv "$T_D0/rename-src" "$T_D0/orphan-dir/rename-dest"
if [ $? -eq 0 ]; then
	echo Orphaned dir allowed a rename
fi

ln "$T_D0/link-src" "$T_D0/orphan-dir/link-dest"
if [ $? -eq 0 ]; then
	echo Orphaned dir allowed a link
fi

ln -s "$T_D0/symlink-src" "$T_D0/orphan-dir/symlink-dest"
if [ $? -eq 0 ]; then
	echo Orphaned dir allowed a symlink
fi

mkdir "$T_D0/orphan-dir/newdir"
if [ $? -eq 0 ]; then
	echo Orphaned dir allowed a mkdir
fi

o_tmpfile_linkat "$T_D0/orphan-dir" "$T_D0/tmpfile"
if [ $? -eq 0 ]; then
	echo Orphaned dir allowed tmpfile/linkat
fi

# Get out of the orphaned directory
cd

t_pass
