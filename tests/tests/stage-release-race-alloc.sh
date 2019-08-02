#
# concurrent stage and release allocation consistency
#

t_require_commands rm mkdir dd cp cmp mv find scoutfs

EACH=4
NR=$((EACH * 4))
DIR="$T_D0/dir"
BLOCKS=256
BYTES=$(($BLOCKS * 4096))

release_file() {
	local path="$1"
	local vers=$(scoutfs stat -s data_version "$path")

	echo "releasing $path" >> "$T_TMP.log"
	scoutfs release "$path" "$vers" 0 $BLOCKS
	echo "released $path" >> "$T_TMP.log"
}

stage_file() {
	local path="$1"
	local vers=$(scoutfs stat -s data_version "$path")

	echo "staging $path" >> "$T_TMP.log"
	scoutfs stage "$path" "$vers" 0 $BYTES \
		"$DIR/good/$(basename $path)"
	echo "staged $path" >> "$T_TMP.log"
}

echo "== create initial files"
mkdir -p "$DIR"/{on,off,good}
for i in $(seq 1 $NR); do
	dd if=/dev/urandom of="$DIR/good/$i" bs=1MiB count=1 status=none
	cp "$DIR/good/$i" "$DIR/on/$i"
done

echo "== race stage and release"
for r in $(seq 1 1000); do

	on=$(find "$DIR"/on/* 2>/dev/null | shuf | head -$EACH)
	off=$(find "$DIR"/off/* 2>/dev/null | shuf | head -$EACH)
	echo r $r on $on off $off >> "$T_TMP.log"

	for f in $on; do
		release_file $f &
	done
	for f in $off; do
		stage_file $f &
	done
	wait

	[ -n "$on" ] && mv $on "$DIR/off/"
	[ -n "$off" ] && mv $off "$DIR/on/"

	for f in $(find "$DIR"/on/* 2>/dev/null); do
		cmp "$f" "$DIR/good/$(basename $f)"
		if [ $? != 0 ]; then
			t_fail "file $f bad!"
		fi
	done
done

t_pass
