#
# verify d_off output of xfs_io is consistent.
#

t_require_commands xfs_io

filt()
{
	grep d_off | cut -d ' ' -f 1,4-
}

echo "== create content"
for s in $(seq 1 7 250); do
	f=$(printf '%*s' $s | tr ' ' 'a')
	touch ${T_D0}/$f
done

echo "== readdir all"
xfs_io -c "readdir -v" $T_D0 | filt

echo "== readdir offset"
xfs_io -c "readdir -v -o 20" $T_D0 | filt

echo "== readdir len (bytes)"
xfs_io -c "readdir -v -l 193" $T_D0 | filt

echo "== introduce gap"
for s in $(seq 57 7 120); do
	f=$(printf '%*s' $s | tr ' ' 'a')
	rm -f ${T_D0}/$f
done
xfs_io -c "readdir -v" $T_D0 | filt

echo "== cleanup"
rm -rf $T_D0

t_pass
