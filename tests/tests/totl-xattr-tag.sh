t_require_commands touch rm setfattr scoutfs find_xattrs

read_xattr_totals()
{
	sync
	scoutfs read-xattr-totals -p "$T_M0"
}

echo "== single file"
touch "$T_D0/file-1"
setfattr -n scoutfs.totl.test.1.2.3 -v 1 "$T_D0/file-1" 2>&1 | t_filter_fs
setfattr -n scoutfs.totl.test.4.5.6 -v 1 "$T_D0/file-1" 2>&1 | t_filter_fs
read_xattr_totals

echo "== multiple files add up"
touch "$T_D0/file-2"
setfattr -n scoutfs.totl.test.1.2.3 -v 1 "$T_D0/file-2" 2>&1 | t_filter_fs
setfattr -n scoutfs.totl.test.4.5.6 -v 1 "$T_D0/file-2" 2>&1 | t_filter_fs
read_xattr_totals

echo "== removing xattr updates total"
setfattr -x scoutfs.totl.test.4.5.6 "$T_D0/file-2" 2>&1 | t_filter_fs
read_xattr_totals

echo "== updating xattr updates total"
setfattr -n scoutfs.totl.test.1.2.3 -v 10 "$T_D0/file-2" 2>&1 | t_filter_fs
read_xattr_totals

echo "== removing files update total"
rm -f "$T_D0/file-1"
read_xattr_totals
rm -f "$T_D0/file-2"
read_xattr_totals

echo "== multiple files/names in one transaction"
for a in $(seq 1 10); do 
	touch "$T_D0/file-$a"
	setfattr -n scoutfs.totl.test.1.2.3 -v $a "$T_D0/file-$a" 2>&1 | t_filter_fs
done
read_xattr_totals
rm -rf "$T_D0"/file-[0-9]*

echo "== testing invalid names"
touch "$T_D0/invalid"
setfattr -n scoutfs.totl.test... -v 10 "$T_D0/invalid" 2>&1 | t_filter_fs
setfattr -n scoutfs.totl.test..2.3 -v 10 "$T_D0/invalid" 2>&1 | t_filter_fs
setfattr -n scoutfs.totl.test.1..3 -v 10 "$T_D0/invalid" 2>&1 | t_filter_fs
setfattr -n scoutfs.totl.test.1.2. -v 10 "$T_D0/invalid" 2>&1 | t_filter_fs
setfattr -n scoutfs.totl.test.1 -v 10 "$T_D0/invalid" 2>&1 | t_filter_fs
setfattr -n scoutfs.totl.test.1.2 -v 10 "$T_D0/invalid" 2>&1 | t_filter_fs

echo "== testing invalid values"
setfattr -n scoutfs.totl.test.1.2.3 -v "+1" "$T_D0/invalid" 2>&1 | t_filter_fs
setfattr -n scoutfs.totl.test.1.2.3 -v "10." "$T_D0/invalid" 2>&1 | t_filter_fs
setfattr -n scoutfs.totl.test.1.2.3 -v "-" "$T_D0/invalid" 2>&1 | t_filter_fs
setfattr -n scoutfs.totl.test.1.2.3 -v "junk10" "$T_D0/invalid" 2>&1 | t_filter_fs
setfattr -n scoutfs.totl.test.1.2.3 -v "10junk" "$T_D0/invalid" 2>&1 | t_filter_fs
rm -f "$T_D0/invalid"

echo "== larger population that could merge"
NR=5000
TOTS=100
CHECK=100
PER_DIR=1000
PER_FILE=10

declare -A totals counts
LOTS="$T_D0/lots"

for i in $(seq 0 $PER_DIR $NR); do
	p="$LOTS/$((i / PER_DIR))"
	mkdir -p $p
done
for i in $(seq 0 $PER_FILE $NR); do
	p="$LOTS/$((i / PER_DIR))/file-$((i / PER_FILE))"
	touch $p
done

for phase in create update remove; do
	for i in $(seq 0 $NR); do
		p="$LOTS/$((i / PER_DIR))/file-$((i / PER_FILE))"

		t=$((i % TOTS))
		n="scoutfs.totl.test-$i.$t.0.0"

		case $phase in 
			create)
				v="$i"
				setfattr -n "$n" -v "$v" "$p" 2>&1 >> $T_TMP.sfa
				((totals[$t]+=$v))
				((counts[$t]++))
				;;
			update)
				v=$((i * 3))
				delta=$((i * 2))
				setfattr -n "$n" -v "$v" "$p" 2>&1 >> $T_TMP.sfa
				((totals[$t]+=$delta))
				;;
			remove)
				v=$((i * 3))
				setfattr -x "$n" "$p" 2>&1 >> $T_TMP.sfa
				((totals[$t]-=$v))
				((counts[$t]--))
				;;
		esac

		if [ "$i" -gt 0 -a "$((i % CHECK))" == "0" ]; then
			echo "checking $phase $i" > $T_TMP.check_arr
			echo "checking $phase $i" > $T_TMP.check_read

			( for k in ${!totals[@]}; do
				echo "$k.0.0 = ${totals[$k]}, ${counts[$k]}"
			  done ) | grep -v "= 0, 0$" | sort -n >> $T_TMP.check_arr

			sync
			read_xattr_totals | sort -n >> $T_TMP.check_read

			diff -u $T_TMP.check_arr $T_TMP.check_read || \
				t_fail "totals read didn't match expected arrays"
		fi
	done
done

rm -rf "$T_D0/merging"

t_pass
