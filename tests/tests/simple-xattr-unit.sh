#
# simple xattr unit tests
#

t_require_commands hexdump setfattr getfattr cmp touch dumb_setxattr

FILE="$T_D0/file"
NR=500

long_string() {
	local chars=$1
	local bytes=$(((chars + 1) / 2))
	local huge

	huge=$(hexdump -vn "$bytes" -e ' /1 "%02x"'  /dev/urandom)
	echo ${huge:0:$chars}

}

# delete each xattr afterwards so they don't accumulate
test_xattr_lengths() {
	local name_len=$1
	local val_len=$2
	local name="user.$(long_string $name_len)"
	local val="$(long_string $val_len)"

	echo "key len $name_len val len $val_len" >> "$T_TMP.log"
	setfattr -n $name -v \"$val\" "$FILE"

	# grep has trouble with enormous args?  so we dump the
	# name=value to a file and compare with a known good file
	getfattr -d --absolute-names "$FILE" | grep "$name" > "$T_TMP.got"

	if [ $val_len == 0 ]; then
		echo "$name" > "$T_TMP.good"
	else
		echo "$name=\"$val\"" > "$T_TMP.good"
	fi
	cmp "$T_TMP.good" "$T_TMP.got" || exit 1

	setfattr -x $name "$FILE"
}

print_and_run() {
	printf '%s\n' "$*" | t_filter_fs
	"$@" || echo "returned nonzero status: $?"
}

echo "=== XATTR_ flag combinations"
touch "$FILE"
print_and_run dumb_setxattr -p "$FILE" -n user.test -v val -c -r
print_and_run dumb_setxattr -p "$FILE" -n user.test -v val -r
print_and_run dumb_setxattr -p "$FILE" -n user.test -v val -c
print_and_run dumb_setxattr -p "$FILE" -n user.test -v val -c
print_and_run dumb_setxattr -p "$FILE" -n user.test -v val -r
rm "$FILE"

echo "=== bad lengths"
touch "$FILE"
setfattr -n \"\" -v val "$FILE" 2>&1 | t_filter_fs
setfattr -n user.$(long_string 256) -v val "$FILE" 2>&1 | t_filter_fs
setfattr -n user.$(long_string 1000) -v val "$FILE" 2>&1 | t_filter_fs
setfattr -n user.name -v $(long_string 65536) "$FILE" 2>&1 | t_filter_fs

# sync to make sure all reserved items are dirtied each time
echo "=== good length boundaries"
# 255 key len - strlen("user.")
for name_len in 1 249 250; do
for val_len in 0 1 254 255 256 65534 65535; do
	sync
	test_xattr_lengths $name_len $val_len
done
done

echo "=== $NR random lengths"
touch "$FILE"
for i in $(seq 1 $NR); do
	name_len=$((1 + (RANDOM % 250)))
	val_len=$((RANDOM % 65536))
	test_xattr_lengths $name_len $val_len
done

t_pass
