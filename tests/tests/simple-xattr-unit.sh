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

	getfattr -d --only-values --absolute-names "$FILE" -n "$name" > "$T_TMP.got"
	echo -n "$val" > "$T_TMP.good"

	cmp "$T_TMP.good" "$T_TMP.got" || \
		t_fail "cmp failed name len $name_len val len $val_len"

	setfattr -x $name "$FILE"
}

print_and_run() {
	printf '%s\n' "$*" | t_filter_fs
	"$@" || echo "returned nonzero status: $?"
}

# fill a buffer with strings that identify their byte offset
offs=""
for o in $(seq 0 7 $((65535 - 7))); do
	offs+="$(printf "[%5u]" $o)"
done

change_val_sizes() {
	local name="$1"
	local file="$2"
	local from="$3"
	local to="$4"

	while : ; do
		setfattr -x "$name" "$file" > /dev/null 2>&1
		setfattr -n "$name" -v "${offs:0:$from}" "$file"
		setfattr -n "$name" -v "${offs:0:$to}" "$file"
		if ! diff -u <(echo -n "${offs:0:$to}") <(getfattr --absolute-names --only-values -n "$name" $file) ; then
			echo "setting $name from $from to $to failed"
		fi

		if [ $from == $3 ]; then
			from=$4
			to=$3
		else
			break
		fi
	done
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

echo "=== alternate val size between interesting sizes"
name="user.test"
ITEM=896
HDR=$((8 + 9))
# one full item apart
change_val_sizes $name "$FILE" $(((ITEM * 2) - HDR)) $(((ITEM * 3) - HDR))
# multiple full items apart
change_val_sizes $name "$FILE" $(((ITEM * 6) - HDR)) $(((ITEM * 9) - HDR))
# item boundary fence posts
change_val_sizes $name "$FILE" $(((ITEM * 5) - HDR - 1)) $(((ITEM * 13) - HDR + 1))
# min and max
change_val_sizes $name "$FILE" 1 65535

t_pass
