#
# test mmap() and normal read/write consistency between different nodes
#

t_require_commands mmap_stress

echo "== mmap_stress"
mmap_stress 10000 3000 "$T_D0/file" "$T_D1/file"

echo "== done"
t_pass
