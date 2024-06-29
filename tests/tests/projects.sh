
# notable id to recognize in output
ID=8675309

echo "== default new files don't have project"
touch "$T_D0/file"
scoutfs get-attr-x -p "$T_D0/file"

echo "== set new project on files and dirs"
mkdir "$T_D0/dir"
scoutfs set-attr-x -p $ID "$T_D0/file"
scoutfs set-attr-x -p $ID "$T_D0/dir"
scoutfs get-attr-x -p "$T_D0/file"
scoutfs get-attr-x -p "$T_D0/dir"

echo "== non-root can see id"
chmod 644 "$T_D0/file"
setpriv --ruid=12345 --euid=12345 scoutfs get-attr-x -p "$T_D0/file"

echo "== can use IDs around long width limits"
touch "$T_D0/ids"
for id in         0x7FFFFFFF         0x80000000         0xFFFFFFFF \
          0x7FFFFFFFFFFFFFFF 0x8000000000000000 0xFFFFFFFFFFFFFFFF; do
	scoutfs set-attr-x -p $id "$T_D0/ids"
	scoutfs get-attr-x -p "$T_D0/ids"
done

echo "== created files and dirs inherit project id"
touch "$T_D0/dir/file"
mkdir "$T_D0/dir/sub"
scoutfs get-attr-x -p "$T_D0/dir/file"
scoutfs get-attr-x -p "$T_D0/dir/sub"

echo "== inheritance continues"
mkdir "$T_D0/dir/sub/more"
scoutfs get-attr-x -p "$T_D0/dir/sub/more"

# .. just inherits 0 :) 
echo "== clearing project id stops inheritance"
scoutfs set-attr-x -p 0 "$T_D0/dir"
touch "$T_D0/dir/another-file"
mkdir "$T_D0/dir/another-sub"
scoutfs get-attr-x -p "$T_D0/dir/another-file"
scoutfs get-attr-x -p "$T_D0/dir/another-sub"

echo "== o_tmpfile creations inherit dir"
scoutfs set-attr-x -p $ID "$T_D0/dir"
o_tmpfile_linkat "$T_D0/dir" "$T_D0/dir/tmpfile"
scoutfs get-attr-x -p "$T_D0/dir/tmpfile"


t_pass
