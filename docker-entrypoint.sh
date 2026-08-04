#!/bin/sh
# rastro hands its output back to $SUDO_UID/$SUDO_GID so the human who ran it can
# read their own results. Inside a container there is no sudo, so nothing sets
# those — and a bind-mounted result directory ends up root-owned and unreadable
# by the user who mounted it.
#
# Derive them from the owner of /out instead, which is the host user's uid/gid
# when -v is used. rastro's existing ownership handback then does the rest, so
# the container needs no special-case code in the tool itself.
#
# With no bind mount, /out is root-owned and this resolves to 0:0 — a harmless
# no-op.
set -e

if [ -d /out ]; then
    SUDO_UID="$(stat -c %u /out)"
    SUDO_GID="$(stat -c %g /out)"
    export SUDO_UID SUDO_GID
fi

exec rastro "$@"
