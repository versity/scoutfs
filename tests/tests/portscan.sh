#
# portscan tests - assure malformed packets do not cause issues
#

t_require_commands scoutfs nc

echo "== empty packets"
sleep 1
echo "    " | nc -p 33033 127.0.0.1 42000
echo "    " | nc -p 33133 127.0.0.1 42001
echo "    " | nc -p 33233 127.0.0.1 42002

echo "== find portscan in connections"
L=$(grep 'peer 127.0.0.1:33.33' /sys/kernel/debug/scoutfs/*/connections)
echo $L

# wait for fencing timeout (20s)
sleep 30

echo "== find portscan in connections"
L=$(grep 'peer 127.0.0.1:33.33' /sys/kernel/debug/scoutfs/*/connections)
echo $L

t_pass
