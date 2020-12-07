#
# basic dirent consistency
#

t_require_mounts 2

# atime isn't consistent
compare_find_stat_on_all_mounts() {
	local path
	local i

	for i in $(t_fs_nrs); do
		eval path="\$T_D${i}/dir"
		find $path | sort | xargs stat | t_filter_fs | \
			grep -v "^Access: [0-9]*" 2>&1 > $T_TMP.stat.$i
	done

	for i in $(t_fs_nrs); do
		diff -u $T_TMP.stat.0 $T_TMP.stat.$i || \
			t_fail "node $i find output differed from node 0"
	done

}

echo "== create per node dirs" 
for i in $(t_fs_nrs); do
	eval path="\$T_D${i}/dir/$i"
	mkdir -p $path
done

echo "== touch files on each node"
for i in $(t_fs_nrs); do
	eval path="\$T_D${i}/dir/$i/$i"
	touch $path
done
compare_find_stat_on_all_mounts

echo "== recreate the files"
for i in $(t_fs_nrs); do
	eval path="\$T_D${i}/dir/$i/$i"
	rm -f $path
	touch $path
done
compare_find_stat_on_all_mounts

echo "== turn the files into directories"
for i in $(t_fs_nrs); do
	eval path="\$T_D${i}/dir/$i/$i"
	rm -f $path
	mkdir $path
done
compare_find_stat_on_all_mounts

echo "== rename parent dirs"
for i in $(t_fs_nrs); do
	eval before="\$T_D${i}/dir/$i"
	eval after="\$T_D${i}/dir/$i-renamed"
	mv $before $after
done
compare_find_stat_on_all_mounts

echo "== rename parent dirs back"
for i in $(t_fs_nrs); do
	eval before="\$T_D${i}/dir/$i-renamed"
	eval after="\$T_D${i}/dir/$i"
	mv $before $after
done
compare_find_stat_on_all_mounts

echo "== create some hard links"
for i in $(t_fs_nrs); do
	eval path="\$T_D${i}/dir/$i/$i.file"
	touch $path
	for link in $(seq 1 3); do
		ln $path $path-$link
	done
done
compare_find_stat_on_all_mounts

echo "== recreate one of the hard links"
for i in $(t_fs_nrs); do
	eval path="\$T_D${i}/dir/$i/$i.file-3"
	rm -f $path
	touch $path
done
compare_find_stat_on_all_mounts

echo "== delete the remaining hard link"
for i in $(t_fs_nrs); do
	eval path="\$T_D${i}/dir/$i/$i.file-2"
	rm -f $path
done
compare_find_stat_on_all_mounts

echo "== race to blow everything away"
pids=""
echo "[nodes are racing to log std(out|err) now..]" >> $T_TMP.log
for i in $(t_fs_nrs); do
	eval path="\$T_D${i}/dir"
	rm -rf "$path/*" >> $T_TMP.log 2>&1 &
	pids="$pids $!"
done
# failure's fine
wait $pids
compare_find_stat_on_all_mounts

t_pass
