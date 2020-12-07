# 
# Concurrently perform archive ops on per-mount sets of files.
#
# Each mount has its own directorie.  Each mount has processes which
# perform operations on the files in the mount directories.
#
# The test is organized as multiple rounds of the processes going
# through phases where they perform an operation on all their files.
#
# The phases are implemented as scripts that perform the operation on
# all the processes' files and which are run concurrently on all the
# mounts during the phase
#
# The test will raise errors if the scripts produce unexpected output or
# exit with non-zero status. 
#

t_require_commands perl md5sum bc cut tr cmp scoutfs

#
# static size config, the rest is derived from mem or fs size
#
ROUNDS=3
PROCS_PER_MOUNT=2
MIN_FILE_BYTES=$((1024 * 1024))
MAX_FILE_BYTES=$((1024 * 1024 * 1024))

hashed_u64()
{
	local str="$1"
	local hex=$(echo "$str" | md5sum | cut -b1-16 | tr a-z A-Z)

	echo "ibase=16; $hex" | bc
}

# random size within min and max for a given file, rounded up to a block
file_bytes()
{
	local path="$1"
	local nr=$(hashed_u64 "$path bytes")
	local bytes=$(echo "($nr % ($MAX_FILE_BYTES - $MIN_FILE_BYTES)) + $MIN_FILE_BYTES" | bc)

	echo "(($bytes + 4095) / 4096) * 4096" | bc
}

# run the named script in the background for each process on each mount
# and wait for them to finish
run_scripts()
{
	local name="$1"
	local script
	local pids=""
	local pid=""
	local rc
	local n
	local p

	for n in $(t_fs_nrs); do
		for p in $(seq 1 $PROCS_PER_MOUNT); do
			script="$T_D0/$name-$n-$p"

			bash "$script" &
			rc="$?"
			pid="$!"
			if [ "$rc" != 0 ]; then
				echo failed to run script $script: rc $rc
				continue
			fi

			echo "script $script pid $pid" >> $T_TMP.log
			pids="$pids $pid"
		done
	done

	for pid in $pids; do
		wait $pid
		rc="$?"
		if [ "$rc" == "127" ]; then
			continue
		fi
		if [ "$rc" != "0" ]; then
			echo "script pid $pid failed: rc $rc"
		fi
	done
}

#
# Given static processes per mount and min and max file sizes, figure
# out the number of file sizes to work with so that all the files
# are limited by half of either fs size or memory, whichever is lesser.
#
echo "== calculate number of files"

# get meg config from lesser of mem or fs capacity
MEM_MEGS=$(free -m | awk '($1 == "Mem:"){print $2}')
if [ "$MEM_MEGS" -lt 256 -o "$MEM_MEGS" -gt $((1024 * 1024 * 1024)) ]; then
	t_fail "host has questionable $meg MiB of mem?"
fi
MEM_MEGS=$((MEM_MEGS / 2))

FS_FREE_BLOCKS=$(stat -f -c '%f' "$T_M0")
FS_BLOCK_SIZE=$(stat -f -c '%S' "$T_M0")
FS_MEGS=$((FS_FREE_BLOCKS * FS_BLOCK_SIZE / (1024 * 1024)))
FS_MEGS=$((FS_MEGS / 2))

if [ "$MEM_MEGS" -lt "$FS_MEGS" ]; then
	TARGET_MEGS=$MEM_MEGS
else
	TARGET_MEGS=$FS_MEGS
fi

# calculated config
AVG_FILE_BYTES=$((MIN_FILE_BYTES + MAX_FILE_BYTES / 2))
TARGET_BYTES=$((TARGET_MEGS * 1024 * 1024))
TARGET_FILES=$((TARGET_BYTES / AVG_FILE_BYTES))
FILES_PER_PROC=$((TARGET_FILES / (PROCS_PER_MOUNT * T_NR_MOUNTS)))
test "$FILES_PER_PROC" -lt 2 && FILES_PER_PROC=2

for a in ROUNDS MIN_FILE_BYTES MAX_FILE_BYTES TARGET_BYTES PROCS_PER_MOUNT \
	AVG_FILE_BYTES TARGET_FILES FILES_PER_PROC MEM_MEGS FS_FREE_BLOCKS \
	FS_BLOCK_SIZE FS_MEGS TARGET_MEGS; do
	eval echo $a=\$$a >> $T_TMP.log
done
	
echo "== create per mount dirs" 
for n in $(t_fs_nrs); do
	eval dir="\$T_D${n}/dir/$n"
	t_quiet mkdir -p "$dir"
done

#
# Our unique file contents pattern are 4k "blocks" written as single
# lines that start with unique identifying values padded with spaces.
#
echo "perl -e 'for (my \$i = 0; \$i < '\$1'; \$i++) { printf(\"mount %020u process %020u file %020u blkno %020u%s\\n\", '\$2', '\$3', '\$4', \$i, \" \" x 3987); }'" > $T_D0/gen

echo "== generate phase scripts"
for n in $(t_fs_nrs); do
	for p in $(seq 1 $PROCS_PER_MOUNT); do
		gen="$T_D0/gen"
		create="$T_D0/create-$n-$p"
		> $create
		verify="$T_D0/verify-$n-$p"
		> $verify
		release="$T_D0/release-$n-$p"
		> $release
		stage="$T_D0/stage-$n-$p"
		> $stage
		online="$T_D0/online-$n-$p"
		> $online
		offline="$T_D0/offline-$n-$p"
		> $offline
		unlink="$T_D0/unlink-$n-$p"
		> $unlink

		for f in $(seq 1 $FILES_PER_PROC); do
			eval path="\$T_D${n}/dir/$n/$p-$f"
			bytes=$(file_bytes "$path")
			blocks=$(echo "$bytes / 4096" | bc)

			echo "bash $gen $blocks $n $p $f > $path" >> $create
			echo "cmp $path <(bash $gen $blocks $n $p $f)" >> $verify
			echo "vers=\$(scoutfs stat -s data_version $path)" >> $release
			echo "scoutfs release $path \$vers 0 $blocks" >> $release
			echo "vers=\$(scoutfs stat -s data_version $path)" >> $stage
			echo "scoutfs stage $path \$vers 0 $bytes <(bash $gen $blocks $n $p $f)" >> $stage
			echo "rm -f $path" >> $unlink

			echo "x=\$(scoutfs stat -s online_blocks $path)" >> $online
			echo "test \$x == $blocks || echo $path has \$x online blocks, expected $blocks" >> $online
			echo "x=\$(scoutfs stat -s offline_blocks $path)" >> $online
			echo "test \$x == 0 || echo $path has \$x offline blocks, expected 0" >> $online

			sed -e 's/online/SWIZZLE/g' -e 's/offline/online/g'  -e 's/SWIZZLE/offline/g' \
				< $online > $offline
		done
	done
done

for i in $(seq 1 $ROUNDS); do
	for a in create online verify \
		release offline \
		stage online verify \
		release offline unlink; do

		echo "== round $i: $a"
		run_scripts "$a"
	done
done

t_pass
