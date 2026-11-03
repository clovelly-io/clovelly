#!/bin/sh
# PID 1 on the verity root. Mounts the writable tmpfs state, loads drivers, brings up
# eth0, puts the base bundle on tmpfs, then:
#   prod: runs cell-agent as its first child (boot, unlock, serve) and powers the VM
#         off when it exits: at cell end, on a refusal or when no unlock comes. That
#         is the recycle.
#   test: reads its role from instance metadata and either runs the harness, returns
#         the results (signed-URL upload if given, always on serial) and powers off;
#         serves as the TCP sink for the transfer benchmark; runs the cell as prod
#         does under `cell-agent test-cell`, which scans the agent's memory when the
#         cell ends (role `cell`); or serves an unverified certificate (role
#         `impostor`), or is the header-logging test destination (role `dest`).

export PATH=/sbin:/bin
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

mount -t tmpfs -o mode=0755 tmpfs /run
mount -t tmpfs tmpfs /tmp
mount -t tmpfs tmpfs /var
ln -s /run /var/run # iproute2 keeps named netns under /var/run/netns
mkdir -p /dev/pts /dev/shm
mount -t devpts devpts /dev/pts
mount -t tmpfs tmpfs /dev/shm
mount -t cgroup2 cgroup2 /sys/fs/cgroup
modprobe configfs && mount -t configfs configfs /sys/kernel/config
# tdx-guest is absent outside a TD; the harness reports what it needs.
for m in af_packet gve tdx-guest veth nft_masq nft_chain_nat nft_redir nft_reject_inet \
    dm-crypt xts aesni-intel ext4 overlay; do modprobe "$m"; done
# One loop device per mounted volume (phase 4); a full cell has at most 42 sandboxes.
modprobe loop max_loop=64
hostname cell
# The egress proxy holds two sockets per sandbox connection (phase 3: at least 2,000).
ulimit -n 262144

ip link set lo up
udhcpc -i eth0 -s /etc/udhcpc.sh -O mtu -t 30 -T 1 -n -q || echo "CLOVELLY-DHCP-FAILED"

# Time from Google's NTP on the metadata server (/etc/chrony.conf): set the clock once
# before the agent starts, then keep it. The host answers NTP, so chronyd runs as its
# own user (keeping only CAP_SYS_TIME) under its seccomp filter.
chronyd -q -t 20 -u chrony -F 1 -f /etc/chrony.conf || echo "CLOVELLY-CHRONY-FIRST-SYNC-FAILED"
chronyd -u chrony -F 1 -f /etc/chrony.conf || echo "CLOVELLY-CHRONY-FAILED"

mkdir -p /run/clovelly/base
cp -a /clovelly/base-bundle/rootfs /run/clovelly/base/rootfs
# The store copy is read-only, and sandboxes run as root without capabilities, so give
# the owner write access to the work directory (writes land in each sandbox's overlay).
chmod u+w /run/clovelly/base/rootfs/work

if [ "$(cat /clovelly/variant)" = prod ]; then
    cell-agent
    echo "cell-agent exited $?; powering off"
    poweroff -f
fi

meta() {
    curl -sf -H 'Metadata-Flavor: Google' \
        "http://169.254.169.254/computeMetadata/v1/instance/attributes/$1"
}

case $(meta clovelly-role) in
sink)
    echo "CLOVELLY-SINK-READY"
    cell-agent sink --listen 0.0.0.0:5201
    poweroff -f
    ;;
cell)
    echo "CLOVELLY-CELL-START"
    cell-agent test-cell
    echo "CLOVELLY-CELL-EXIT $?"
    sleep 30
    poweroff -f
    ;;
impostor)
    cell-agent impostor --mode "$(meta clovelly-impostor-mode)" --name "$(meta clovelly-impostor-name)"
    poweroff -f
    ;;
dest)
    cell-agent dest
    echo "CLOVELLY-DEST-EXIT $?"
    sleep 30
    poweroff -f
    ;;
esac

tests=$(meta clovelly-tests)
peer=$(meta clovelly-peer)
concurrency=$(meta clovelly-concurrency)
samples=$(meta clovelly-samples)
url=$(meta clovelly-results-url)

mkdir -p /run/results
echo "CLOVELLY-HARNESS-START tests=$tests"
cell-agent harness --out /run/results --tests "$tests" \
    ${peer:+--peer "$peer"} ${concurrency:+--concurrency "$concurrency"} \
    ${samples:+--samples "$samples"} 2>&1
echo "CLOVELLY-HARNESS-EXIT $?"

dmesg > /run/results/dmesg.txt
tar -C /run -czf /run/results.tgz results
dmesg -n 1
if [ -n "$url" ]; then
    if curl -sf -X PUT -H 'Content-Type: application/gzip' --upload-file /run/results.tgz "$url"; then
        echo "CLOVELLY-UPLOAD-OK"
    else
        echo "CLOVELLY-UPLOAD-FAILED"
    fi
fi
echo "CLOVELLY-RESULTS-BEGIN"
base64 /run/results.tgz
echo "CLOVELLY-RESULTS-END"
sync
# The job reads the console every few seconds; give it time to see the end.
sleep 30
poweroff -f
