
#
# Test _GET_REFERRING_ENTRIES ioctl via the get-referring-entries cli
# command
#

# consistently print only entry names
filter_names() {
	exec cut -d ' ' -f 8- | sort
}

# print entries with type characters to match find.  not happy with hard
# coding, but abi won't change much.
filter_types() {
	exec cut -d ' ' -f 5- | \
	sed \
		-e 's/type 1 /type p /' \
		-e 's/type 2 /type c /' \
		-e 's/type 4 /type d /' \
		-e 's/type 6 /type b /' \
		-e 's/type 8 /type f /' \
		-e 's/type 10 /type l /' \
		-e 's/type 12 /type s /' \
		| \
	sort
}

n_chars() {
	local n="$1"
	printf 'A%.0s' $(eval echo {1..\$n})
}

GRE="scoutfs get-referring-entries -p $T_M0"

echo "== root inode returns nothing"
$GRE 1

echo "== crazy large unused inode does nothing"
$GRE 4611686018427387904 # 1 << 62

echo "== basic entry"
touch $T_D0/file
ino=$(stat -c '%i' $T_D0/file)
$GRE $ino | filter_names

echo "== rename"
mv $T_D0/file $T_D0/renamed
$GRE $ino | filter_names

echo "== hard link"
mv $T_D0/renamed $T_D0/file
ln $T_D0/file $T_D0/link
$GRE $ino | filter_names

echo "== removal"
rm $T_D0/file $T_D0/link
$GRE $ino

echo "== different dirs"
touch $T_D0/file
ino=$(stat -c '%i' $T_D0/file)
for i in $(seq 1 10); do
	mkdir $T_D0/dir-$i
	ln $T_D0/file $T_D0/dir-$i/file-$i
done
diff -u <(find $T_D0 -type f -printf '%f\n' | sort) <($GRE $ino | filter_names)
rm $T_D0/file

echo "== file types"
mkdir $T_D0/dir
touch $T_D0/dir/file
mkdir $T_D0/dir/dir
ln -s $T_D0/dir/file $T_D0/dir/symlink
mknod $T_D0/dir/char c 1 3 # null
mknod $T_D0/dir/block b 7 0 # loop0
for name in $(ls -UA $T_D0/dir | sort); do
	ino=$(stat -c '%i' $T_D0/dir/$name)
	$GRE $ino | filter_types
done
rm -rf $T_D0/dir

echo "== all name lengths work"
mkdir $T_D0/dir
touch $T_D0/dir/file
ino=$(stat -c '%i' $T_D0/dir/file)
name=""
> $T_TMP.unsorted
for i in $(seq 1 255); do
	name+="a"
	echo "$name" >> $T_TMP.unsorted
	ln $T_D0/dir/file $T_D0/dir/$name
done
sort $T_TMP.unsorted > $T_TMP.sorted
rm $T_D0/dir/file
$GRE $ino | filter_names > $T_TMP.gre
diff -u $T_TMP.sorted $T_TMP.gre
rm -rf $T_D0/dir

t_pass
