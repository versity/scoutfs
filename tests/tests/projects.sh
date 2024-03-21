
echo "== default new files don't have project"
touch "$T_D0/file"
scoutfs project-id -g "$T_D0/file"

echo "== set new project on files and dirs"
mkdir "$T_D0/dir"
scoutfs project-id -s 1 "$T_D0/file" "$T_D0/dir"
scoutfs project-id -g "$T_D0/file" "$T_D0/dir"

echo "== can use interesting IDs"
touch "$T_D0/ids"
for id in         0x7FFFFFFF         0x80000000         0xFFFFFFFF \
          0x7FFFFFFFFFFFFFFF 0x8000000000000000 0xFFFFFFFFFFFFFFFF; do
	scoutfs project-id -s $id "$T_D0/ids"
	scoutfs project-id -g "$T_D0/ids"
done

echo "== created files and dirs inherit project id"
touch "$T_D0/dir/file"
mkdir "$T_D0/dir/sub"
scoutfs project-id -g "$T_D0/dir/file" "$T_D0/dir/sub"

echo "== inheritance continues"
mkdir "$T_D0/dir/sub/more"
scoutfs project-id -g "$T_D0/dir/sub/more"

# .. just inherits 0 :) 
echo "== clearing project id stops inheritance"
scoutfs project-id -s 0 "$T_D0/dir"
touch "$T_D0/dir/another-file"
mkdir "$T_D0/dir/another-sub"
scoutfs project-id -g "$T_D0/dir/another-file" "$T_D0/dir/another-sub"

echo "== o_tmpfile creations inherit dir"
scoutfs project-id -s 1 "$T_D0/dir"
o_tmpfile_linkat "$T_D0/dir" "$T_D0/dir/tmpfile"
scoutfs project-id -g "$T_D0/dir/tmpfile"

t_pass
