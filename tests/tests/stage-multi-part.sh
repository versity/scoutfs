#
# Stage a large file in multiple parts and have a reader read it while
# it's being staged.  This has found problems with extent access
# locking.
#

t_require_commands scoutfs perl cmp rm

FILE_BYTES=$((4 * 1024 * 1024 * 1024))
FILE_BLOCKS=$((FILE_BYTES / 4096))
FRAG_BYTES=$((128 * 1024 * 1024))
FRAG_BLOCKS=$((FRAG_BYTES / 4096))
NR_FRAGS=$((FILE_BLOCKS / FRAG_BLOCKS))

#
# high bandwidth way to generate file contents with predictable
# contents.  We use ascii lines with the block identity, padded to 4KB
# with spaces.
#
# $1 is number of 4k blocks to write, and each block gets its block
# number in the line.  $2, $3, and $4 are fields that are put in every
# block.
#
gen() {
	perl -e 'for (my $i = 0; $i < '$1'; $i++) { printf("mount %020u process %020u file %020u blkno %020u%s\n", '$2', '$3', '$4', $i, " " x 3987); }'
}

release_file() {
        local path="$1"
        local vers=$(scoutfs stat -s data_version "$path")

        scoutfs release "$path" -V "$vers" -o 0 -l $FILE_BYTES
}

stage_file() {
        local path="$1"
        local vers=$(scoutfs stat -s data_version "$path")
        local off=0

	for a in $(seq 1 $NR_FRAGS); do
		scoutfs stage <(gen $FRAG_BLOCKS $a $a $a) "$path" -V "$vers" \
			-o $off -l $FRAG_BYTES
		((off+=$FRAG_BYTES))
	done
}

FILE="$T_D0/file"

whole_file() {
	for a in $(seq 1 $NR_FRAGS); do
		gen $FRAG_BLOCKS $a $a $a
	done
}

#
# just one pass through the file.
#

whole_file > "$FILE"
release_file "$FILE"

cmp "$FILE" <(whole_file) &
pid=$!

stage_file "$FILE"

wait $pid || t_fail "comparison failed"

t_pass
