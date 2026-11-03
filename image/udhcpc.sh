#!/bin/sh
# udhcpc event hook: configures the interface from the DHCP lease. GCE leases a /32
# whose gateway is on-link, so the gateway route goes in before the default route.

case "$1" in
deconfig)
    ip addr flush dev "$interface"
    ip link set "$interface" up
    ;;
bound | renew)
    ip addr flush dev "$interface"
    ip addr add "$ip/${mask:-32}" dev "$interface"
    [ -n "$mtu" ] && ip link set "$interface" mtu "$mtu"
    for r in $router; do
        ip route replace "$r" dev "$interface"
        ip route replace default via "$r" dev "$interface"
        break
    done
    : > /run/resolv.conf
    for d in $dns; do echo "nameserver $d" >> /run/resolv.conf; done
    ;;
esac
