#
# Unmount Server and unmount a client as it's replaying to a remaining server
#

majority_nr=$(t_majority_count)
quorum_nr=$T_QUORUM

test "$quorum_nr" == "$majority_nr" && \
        t_skip "all quorum members make up majority, need more mounts to unmount"

test "$T_NR_MOUNTS" -lt "$T_QUORUM" && \
        t_skip "Need enough non-quorum clients to unmount"

for i in $(t_fs_nrs); do
        mounted[$i]=1
done

LENGTH=60
echo "== ${LENGTH}s of unmounting non-quorum clients during recovery"
END=$((SECONDS + LENGTH))
while [ "$SECONDS" -lt "$END" ]; do
        sv=$(t_server_nr)
        rid=$(t_mount_rid $sv)
        echo "sv $sv rid $rid" >> "$T_TMP.log"
        sync
        t_umount $sv &

        for i in $(t_fs_nrs); do
                if [ "$i" -ge "$quorum_nr" ]; then
                        t_umount $i &
                        echo "umount $i rid $rid quo $quorum_nr" \
                                >> $T_TMP.log
                        mounted[$i]=0
                fi
        done

        wait

        t_mount $sv &
        for i in $(t_fs_nrs); do
                if [ "${mounted[$i]}" == 0 ]; then
                        t_mount $i &
                fi
        done

        wait

        declare RID_LIST=$(cat /sys/fs/scoutfs/*/rid | sort -u)
        read -a rid_arr <<< $RID_LIST

        declare LOCK_LIST=$(cut -d' ' -f 5 /sys/kernel/debug/scoutfs/*/server_locks | sort -u)
        read -a lock_arr <<< $LOCK_LIST

        for i in "${lock_arr[@]}"; do
                if [[ ! " ${rid_arr[*]} " =~ " $i " ]]; then
                        echo -e "RID($i) exists" >> $T_TMP.log
                        echo -e "rid_arr:\n${rid_arr[@]}" >> $T_TMP.log
                        echo -e "lock_arr:\n${lock_arr[@]}" >> $T_TMP.log
                        t_fail "RID($i): exists when not mounted"
                fi
        done
done

t_pass
