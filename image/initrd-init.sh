#!/bin/busybox sh
# Initrd: open the root partition through dm-verity with the root hash from the UKI's
# command line (clovelly.roothash=), mount it read-only and switch to it. Any failure
# powers the VM off, so a tampered root never boots.

/bin/busybox mkdir -p /proc /sys /dev /sysroot
/bin/busybox --install -s /bin
# kmod (in /sbin) must win over busybox's modprobe, which cannot load xz modules.
export PATH=/sbin:/bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

fail() {
    echo "CLOVELLY-BOOT-FAILED: $*" > /dev/console
    dmesg | grep -iE 'verity|erofs|nvme|device-mapper' | tail -n 20 > /dev/console
    # Leave the console readable for a while before the VM stops.
    sleep 30
    poweroff -f
}

roothash=
for arg in $(cat /proc/cmdline); do
    case "$arg" in clovelly.roothash=*) roothash=${arg#clovelly.roothash=} ;; esac
done
# image-test-wrong-roothash only: open the real root whatever the command line says,
# so the cell agent's own check (command line vs mounted root) is what refuses it.
[ -f /etc/clovelly-pinned-roothash ] && roothash=$(cat /etc/clovelly-pinned-roothash)
[ -n "$roothash" ] || fail "no clovelly.roothash= on the kernel command line"

modprobe -a nvme dm-verity erofs || fail "loading nvme, dm-verity and erofs"

# Partition 2 is root, partition 3 its hash tree (see image/default.nix).
i=0
while [ ! -b /dev/nvme0n1p3 ]; do
    i=$((i + 1))
    [ "$i" -le 300 ] || fail "no /dev/nvme0n1p3 after 30 s"
    sleep 0.1
done

# No udev here: libdevmapper creates /dev/mapper/root itself.
DM_DISABLE_UDEV=1 veritysetup open /dev/nvme0n1p2 root /dev/nvme0n1p3 "$roothash" \
    || fail "veritysetup open"
mount -t erofs -o ro /dev/mapper/root /sysroot || fail "mounting the verity root"

for fs in proc sys dev; do mount --move /$fs /sysroot/$fs; done
exec switch_root /sysroot /init
