#!/bin/sh
#
# Obelisk container entrypoint.
#
# It does the two things that have to happen before the binary can run and that
# the binary itself has no business doing, then gets out of the way. Everything
# else — configuration, core selection, process supervision — is Obelisk's job.

set -eu

OBELISK_DIR="${OBELISK_DIR:-/etc/obelisk}"

# TUN mode needs /dev/net/tun. Docker gives the container a private /dev that
# does not contain it, even when the host module is loaded and NET_ADMIN has
# been granted, so the node is created here unless the host device was mapped in.
if [ ! -c /dev/net/tun ]; then
    mkdir -p /dev/net
    if mknod /dev/net/tun c 10 200 2>/dev/null; then
        chmod 600 /dev/net/tun
    else
        echo "obelisk: /dev/net/tun is unavailable and could not be created." >&2
        echo "obelisk: TUN mode will not work. Either map the device with" >&2
        echo "obelisk:   --device /dev/net/tun" >&2
        echo "obelisk: or run with -mode tproxy instead." >&2
    fi
fi

# The state directory is a volume, so it may be empty on the very first start.
mkdir -p "${OBELISK_DIR}/bin"

exec /usr/local/bin/obelisk "$@"
