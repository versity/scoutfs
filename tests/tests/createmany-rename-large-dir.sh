#
# We've had bugs where client transactions weren't properly being
# committed as their allocators ran out of resources for the amount of
# log btree dirtying they'd need to do for the size of their dirty item
# cache pages.
#
# This stresses those heuristics by trying to maximize the number of
# btree blocks dirtied for each dirty item cache page.  We create an
# enormous directory and then randomly rename entries in it.
#
# With the bad client commit heuristics this would reliably fail before
# a few thousand renames.
#

t_require_commands createmany mv mkdir

# 298 dirents per 64k block, 4096 max meta avail -- often fewer
NR=$((298 * 4096))
RENAMES=5000

DIR="$T_D0/dir/"

echo "== create large directory with $NR files"
t_quiet mkdir -p "$DIR"
./src/createmany -o "$DIR/f-" $NR > "$T_TMP.createmany.stdout"

echo "== randomly renaming $RENAMES files"
for i in $(seq 1 $RENAMES); do
        rnd=$(((1$RANDOM$RANDOM) % NR))
        orig="$DIR/f-$rnd"
        tmp="$DIR/f-$rnd.$i"

        mv "$orig" "$tmp"
        mv "$tmp" "$orig"
done

t_quiet rm -rf "$DIR"

t_pass
