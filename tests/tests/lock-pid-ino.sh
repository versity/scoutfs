#
# verify debugfs client_locks reports per-mode last-user PID and inode.
#

t_require_commands stat touch awk rm

FILE="$T_D0/file"

echo "== set up file"
touch "$FILE"
INO=$(stat -c %i "$FILE")
GROUP_START=$(( INO & ~1023 ))

echo "== exercise read, write, and write-only modes"
t_quiet stat "$FILE"
echo data > "$FILE"
rm -f "$FILE"

echo "== verify FS-zone lock recorded read and write ino+pid"
ERR=$(awk -v group="$GROUP_START" -v ino="$INO" '
	$2 == "16." group ".0.0.0.0" {
		if ($25 != ino || $32 <= 0)
			print "read mode: ino=" $25 " pid=" $32 " want ino=" ino " pid>0"
		if ($27 != ino || $34 <= 0)
			print "write mode: ino=" $27 " pid=" $34 " want ino=" ino " pid>0"
		found = 1
	}
	END { if (!found) print "no FS-zone client_locks line for group " group }
' < "$(t_debugfs_path)/client_locks")
[ -n "$ERR" ] && t_fail "$ERR"

echo "== verify orphan-zone lock recorded write-only ino+pid"
ERR=$(awk -v ino="$INO" '
	$2 == "8.0.4.0.0.0" {
		if ($29 != ino || $36 <= 0)
			print "write-only mode: ino=" $29 " pid=" $36 " want ino=" ino " pid>0"
		found = 1
	}
	END { if (!found) print "no orphan-zone client_locks line" }
' < "$(t_debugfs_path)/client_locks")
[ -n "$ERR" ] && t_fail "$ERR"

echo "== contend on a single inode with concurrent read and write loops"
FILE2="$T_D0/file2"
touch "$FILE2"
INO2=$(stat -c %i "$FILE2")
GROUP2=$(( INO2 & ~1023 ))

for i in $(seq 1 5); do t_quiet stat "$FILE2"; done &
RPID=$!
for i in $(seq 1 5); do echo $i > "$FILE2"; done &
WPID=$!
wait $RPID $WPID

echo "== verify both rd and wr slots populated by concurrent contention"
ERR=$(awk -v group="$GROUP2" -v ino="$INO2" '
	$2 == "16." group ".0.0.0.0" {
		if ($25 != ino || $32 <= 0)
			print "concurrent read: ino=" $25 " pid=" $32 " want ino=" ino " pid>0"
		if ($27 != ino || $34 <= 0)
			print "concurrent write: ino=" $27 " pid=" $34 " want ino=" ino " pid>0"
		found = 1
	}
	END { if (!found) print "no FS-zone client_locks line for group " group }
' < "$(t_debugfs_path)/client_locks")
[ -n "$ERR" ] && t_fail "$ERR"

t_pass
