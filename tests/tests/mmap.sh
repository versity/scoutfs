#
# test mmap() and normal read/write consistency between different nodes
#
# This script opens a file with a fixed size and writes a pattern
# at random offset with random length, and then reads it again.
#
# writes-reads are performed using "pwrite,mread" and "mwrite,pread"
# pairs, making sure that either method accessing the data that is written
# from one mount (client) is identical to a client from another mount.
#
# The script further alternates write/read by skipping some patterns, e.g.
# the script sometimes does "pwrite-mread" and then "mwrite-pread" on the
# same off/len, and sometimes (25%) skip "mwrite-pread" and other times
# (25%) skip "pwrite-mread".
#
# at all times a checksum "known-good" pattern is pwrite-pread into a separate
# file.
#
# all final output read from the reads is then compared against the known
# good value using sha1sum
#

t_require_commands xfs_io sha1sum grep test

#
# This array contains SEED:OFF:LEN pairs.
#
# It was generated using this simple lua script:
# ```
# function round16(x) return 16 * math.floor(x/16+0.5) ; end
# for i = 1, 65 do
#     print(math.random(1024) .. ":" .. round16(math.random(0,1024*1024 - 65536)) .. ":" .. round16(math.random(256,65536)))
# end
# ```
#
# Note that off+len <= 1mb
#

E=(
861:387696:51376
818:896192:13152
344:755200:18384
568:469296:41312
374:504688:62416
939:624928:47088
146:596672:1328
249:134912:52752
161:394144:8736
112:981984:14512
526:824880:40256
304:626736:34480
506:956272:19344
790:517808:50512
410:876416:18752
361:794032:60256
72:933232:34592
89:188960:43552
912:342976:4448
21:449936:4368
244:954176:59152
872:262144:35488
385:747360:33712
684:522592:2816
449:916032:61024
739:279472:48464
656:348048:45168
170:432640:57712
850:324736:15200
915:344416:45088
980:578656:43168
880:432112:60576
408:800944:44928
933:474304:14352
974:904528:9888
903:630208:28448
635:276288:51568
315:439456:15024
193:271552:36576
427:166736:59456
106:123936:32592
779:968048:61296
701:376688:49200
378:289168:15424
599:240272:10208
750:123344:52048
169:732432:5120
973:51632:34304
181:235984:52336
751:645424:63408
655:746848:6352
139:511392:5360
72:201184:30384
840:563600:49584
54:155136:65536
210:874864:8448
1022:53136:57088
75:4096:60512
609:177312:10912
402:897536:53760
368:543120:38080
464:675728:6768
544:744448:20128
1017:567184:57552
766:618240:2576
)

# test file overall size
SIZE=$((1024 * 1024))

# our test file, accessed through 2 mounts
FILE_V="$T_D2/val"
FILE_P="$T_D0/file"
FILE_M="$T_D1/file"

echo "== create test file"
xfs_io \
	-c "open -ft ${FILE_P}" \
	-c "falloc 0 ${SIZE}"

for SIDE in 0 1 2; do
for N in $(seq 0 $(( ${#E[@]} - 1 )) ); do
	# seed is used to write a different byte pattern
	SEED=$(echo ${E[$N]} | cut -d: -f1)

	OFF=$(echo ${E[$N]} | cut -d: -f2)
	LEN=$(echo ${E[$N]} | cut -d: -f3)

	echo "== $N side $SIDE"

	xfs_io \
		-c "open -ft ${FILE_V}"			\
		-c "falloc 0 ${SIZE}"			\
		-c "pwrite -S ${SEED} ${OFF} ${LEN}"	\
		-c "pread -v ${OFF} ${LEN}"		\
		-c "close"				\
		| grep -v -e ops.sec -e bytes.at.offset | sha1sum

	# write through normal writes, read through mmap
	test $SIDE -eq 0 &&
	xfs_io \
		-c "open ${FILE_P}"			\
		-c "pwrite -S ${SEED} ${OFF} ${LEN}"	\
		-c "close"				\
		-c "open ${FILE_M}"			\
		-c "mmap -rw 0 ${SIZE}"			\
		-c "mread -v ${OFF} ${LEN}"		\
		-c "close"				\
		| grep -v -e ops.sec -e bytes.at.offset | sha1sum

	# write through mmap, read through mmap
	test $SIDE -eq 1 &&
	xfs_io \
		-c "open ${FILE_P}"			\
		-c "mmap -rw 0 ${SIZE}"			\
		-c "mwrite -S ${SEED} ${OFF} ${LEN}"	\
		-c "close"				\
		-c "open ${FILE_M}"			\
		-c "mmap -rw 0 ${SIZE}"			\
		-c "mread -v ${OFF} ${LEN}"		\
		-c "close"				\
		| grep -v -e ops.sec -e bytes.at.offset | sha1sum

	# write throuth mmap, read through normal read
	test $SIDE -eq 2 &&
	xfs_io \
		-c "open ${FILE_M}"			\
		-c "mmap -rw 0 ${SIZE}"			\
		-c "mwrite -S ${SEED} ${OFF} ${LEN}"	\
		-c "close"				\
		-c "open ${FILE_P}"			\
		-c "pread -v ${OFF} ${LEN}"		\
		-c "close"				\
		| grep -v -e ops.sec -e bytes.at.offset | sha1sum

done

echo "== final validate $SIDE side"
sha1sum < "${FILE_P}"
sha1sum < "${FILE_M}"

done

echo "== cleanup"
rm -f "${FILE_P}"

t_pass
