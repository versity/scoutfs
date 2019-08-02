#
# Create a lot of files with large names.  In the past this caught bugs
# in the btree code as it stored manifest entries with large keys that
# stored directory entry names.  Now keys are a small fixed size so this
# has less of an effect.
#

t_require_commands createmany

DIRS="0 1 2 3"
COUNT=100000
for i in $DIRS; do
	d="$T_D0/$i"
	mkdir -p "$d"
	# Use an absurdly long file name to blow the dirent key sizes out
	./src/createmany -o $d/file_$(printf "a%.0s" {1..195})_$i $COUNT \
		>> $T_TMP.log &
done

wait

t_pass
