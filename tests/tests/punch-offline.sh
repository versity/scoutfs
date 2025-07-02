
t_require_commands scoutfs dd fallocate

FILE="$T_D0/file"
DIR="$T_D0/dir"

echo "== can't hole punch dir or special =="
rm -rf $DIR && mkdir -p $DIR
scoutfs punch-offline $DIR -o 0 -l 4096 -V 0

echo "== punching an empty file does nothing =="
rm -f $FILE && touch $FILE
scoutfs punch-offline $FILE -o 0 -l 4096 -V 0

echo "== punch outside of i_size does nothing =="
dd if=/dev/zero of=$FILE bs=4096 count=1 status=none
scoutfs punch-offline $FILE -o 4096 -l 4096 -V 1

echo "== can't hole punch online extent =="
scoutfs get-fiemap -Lb $FILE
scoutfs punch-offline $FILE -o 0 -l 4096 -V 1
scoutfs get-fiemap -Lb $FILE

echo "== can't hole punch unwritten extent =="
rm -rf $FILE && touch $FILE
fallocate -l $((4096 * 3)) $FILE
vers=$(scoutfs stat -s data_version "$FILE")
scoutfs get-fiemap -Lb $FILE
scoutfs punch-offline $FILE -o 4096 -l 4096 -V $vers
scoutfs get-fiemap -Lb $FILE

echo "== hole punch offline extent =="
rm -rf $FILE && touch $FILE
fallocate -l $((4096 * 3)) $FILE
vers=$(scoutfs stat -s data_version "$FILE")
scoutfs release $FILE --data-version $vers
scoutfs get-fiemap -Lb $FILE
scoutfs punch-offline $FILE -o 4096 -l 4096 -V $vers
scoutfs get-fiemap -Lb $FILE

echo "== can't hole punch non-aligned bsz offset or len =="
rm -rf $FILE && touch $FILE
fallocate -l $((4096 * 3)) $FILE
vers=$(scoutfs stat -s data_version "$FILE")
scoutfs release $FILE --data-version $vers
scoutfs get-fiemap -Lb $FILE
scoutfs punch-offline $FILE -o 4095 -l 4096 -V $vers
scoutfs punch-offline $FILE -o 1 -l 4096 -V $vers
scoutfs punch-offline $FILE -o 4096 -l 409700 -V $vers
scoutfs punch-offline $FILE -o 4096 -l 4097 -V $vers
scoutfs punch-offline $FILE -o 4096 -l 4095 -V $vers
scoutfs punch-offline $FILE -o 4096 -l 1 -V $vers
scoutfs punch-offline $FILE -o 4096 -l 0 -V $vers
scoutfs get-fiemap -Lb $FILE

echo "== can't hole punch mismatched data_version =="
rm -rf $FILE && touch $FILE
fallocate -l $((4096 * 3)) $FILE
vers=$(scoutfs stat -s data_version "$FILE")
scoutfs release $FILE --data-version $vers
scoutfs get-fiemap -Lb $FILE
scoutfs punch-offline $FILE -o 4096 -l 4096 -V 0
scoutfs punch-offline $FILE -o 4096 -l 4096 -V 2
scoutfs punch-offline $FILE -o 4096 -l 4096 -V 9999
scoutfs get-fiemap -Lb $FILE

echo "== Punch hole crossing multiple extents =="
rm -rf $FILE && touch $FILE
fallocate -l $((7 * 4096)) $FILE
vers=$(scoutfs stat -s data_version "$FILE")
scoutfs release $FILE --data-version $vers
scoutfs get-fiemap -L $FILE
scoutfs punch-offline $FILE -o $((1 * 4096)) -l 4096 -V $vers
scoutfs punch-offline $FILE -o $((3 * 4096)) -l 4096 -V $vers
scoutfs punch-offline $FILE -o $((5 * 4096)) -l 4096 -V $vers
# 0.1.2.3
scoutfs get-fiemap -L $FILE
scoutfs punch-offline $FILE -o $((2 * 4096)) -l $((3 * 4096)) -V $vers
# 0.....1
scoutfs get-fiemap -L $FILE

echo "== punch hole starting at a hole =="
rm -rf $FILE && touch $FILE
fallocate -l $((7 * 4096)) $FILE
vers=$(scoutfs stat -s data_version "$FILE")
scoutfs release $FILE --data-version $vers
scoutfs get-fiemap -L $FILE
scoutfs punch-offline $FILE -o $((1 * 4096)) -l 4096 -V $vers
scoutfs punch-offline $FILE -o $((3 * 4096)) -l 4096 -V $vers
scoutfs punch-offline $FILE -o $((5 * 4096)) -l 4096 -V $vers
# 0.1.2.3
scoutfs get-fiemap -L $FILE
scoutfs punch-offline $FILE -o $((1 * 4096)) -l $((5 * 4096)) -V $vers
# 0.....1
scoutfs get-fiemap -L $FILE

echo "== large punch =="
rm -rf $FILE && touch $FILE
fallocate -l $((6 * 1024 * 1024 * 1024)) $FILE
vers=$(scoutfs stat -s data_version "$FILE")
scoutfs release $FILE --data-version $vers
scoutfs get-fiemap -L $FILE
scoutfs punch-offline $FILE -o $((134123 * 4096)) -l $((68343 * 4096)) -V $vers
scoutfs punch-offline $FILE -o $((467273 * 4096)) -l $((68343 * 4096)) -V $vers
scoutfs punch-offline $FILE -o $((734623 * 4096)) -l $((68343 * 4096)) -V $vers
scoutfs get-fiemap -L $FILE

echo "== overlapping punches with lots of extents =="
rm -rf $FILE && touch $FILE
fallocate -l $((4096 * 1024)) $FILE
vers=$(scoutfs stat -s data_version "$FILE")
scoutfs release $FILE --data-version 1
scoutfs get-fiemap -Lb $FILE
# punch odd ones away
for h in $(seq 1 2 1023); do
	scoutfs punch-offline $FILE -o $((h * 4096)) -l 4096 -V $vers
done
scoutfs get-fiemap -Lb $FILE | tail -n 1
# punch a large hole from 32 to 55, removing 7 extents
scoutfs punch-offline $FILE -o $((32 * 4096)) -l $((13 * 4096)) -V $vers
scoutfs get-fiemap -Lb $FILE | tail -n 1
# punch every 8th @6
for h in $(seq 6 8 1024); do
	scoutfs punch-offline $FILE -o $((h * 4096)) -l 4096 -V $vers
done
# again @4
scoutfs get-fiemap -Lb $FILE | tail -n 1
for h in $(seq 4 8 1024); do
	scoutfs punch-offline $FILE -o $((h * 4096)) -l 4096 -V $vers
done
scoutfs get-fiemap -Lb $FILE | tail -n 1
# punching a large hole from 127 to 175, removing 12 extents
scoutfs punch-offline $FILE -o $((127 * 4096)) -l $((48 * 4096)) -V $vers
scoutfs get-fiemap -Lb $FILE
# again @2
for h in $(seq 2 8 1024); do
	scoutfs punch-offline $FILE -o $((h * 4096)) -l 4096 -V $vers
done
scoutfs get-fiemap -L $FILE
# and again @0, punching away everything remaining extent
for h in $(seq 0 8 1024); do
	scoutfs punch-offline $FILE -o $((h * 4096)) -l 4096 -V $vers
done
scoutfs get-fiemap -Lb $FILE

t_pass
