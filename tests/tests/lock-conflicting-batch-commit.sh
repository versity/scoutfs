#
# If bulk work accidentally conflicts in the worst way we'd like to have
# it not result in catastrophic performance.  Make sure that each
# instance of bulk work is given the opportunity to get as much as it
# can into the transaction under a lock before the lock is revoked
# and the transaction is committed.
#

t_require_commands setfattr
t_require_mounts 2

NR=3000

echo "== create per mount files" 
for m in 0 1; do 
	eval dir="\$T_D${m}/dir/$m"
	t_quiet mkdir -p "$dir"
	for a in $(seq 1 $NR); do touch "$dir/$a"; done
done

echo "== time independent modification"
for m in 0 1; do 
	eval dir="\$T_D${m}/dir/$m"
	START=$SECONDS
	for a in $(seq 1 $NR); do
		setfattr -n user.test_grace -v $a "$dir/$a"
	done
	echo "mount $m: $((SECONDS - START))" >> $T_TMP.log
done

echo "== time concurrent independent modification"
START=$SECONDS
for m in 0 1; do 
	eval dir="\$T_D${m}/dir/$m"
	(for a in $(seq 1 $NR); do
		setfattr -n user.test_grace -v $a "$dir/$a"; 
	done) &
done
wait
IND="$((SECONDS - START))"
echo "ind: $IND" >> $T_TMP.log

echo "== time concurrent conflicting modification"
START=$SECONDS
for m in 0 1; do 
	eval dir="\$T_D${m}/dir/0"
	(for a in $(seq 1 $NR); do
		setfattr -n user.test_grace -v $a "$dir/$a"; 
	done) &
done
wait
CONF="$((SECONDS - START))"
echo "conf: $IND" >> $T_TMP.log

if [ "$CONF" -gt "$((IND * 5))" ]; then
	t_fail "conflicting $CONF secs is more than 5x independent $IND secs"
fi

t_pass
