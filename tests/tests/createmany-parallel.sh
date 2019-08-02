#
# Run createmany in parallel, make sure we don't crash or throw errors
#

t_require_commands createmany

DIRS="0 1 2 3"
COUNT=1000
for i in $DIRS; do
    d="$T_D0/$i"
    echo "Run createmany in $d" | t_filter_fs
    mkdir -p "$d"
    createmany -o "$d/file_$i" $COUNT >> $T_TMP.log &
done

wait

for i in $DIRS; do
    rm -fr "$T_D0/$i"
done

t_pass
