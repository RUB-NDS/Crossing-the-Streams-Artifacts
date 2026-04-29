#!/bin/sh
# Pre-resolve sibling container hostnames into /etc/hosts so the main
# process never queries Docker's embedded DNS resolver (127.0.0.11) during
# the attack. NSS resolves `files` before `dns`, so static entries here
# bypass the resolver.
#
# Why: at >=25 parallel stacks, the embedded resolver drops UDP queries
# under burst load (visible as ClientConnectorDNSError, EAI_AGAIN, or
# "Temporary failure in name resolution"). Container IPs are stable for
# the container's lifetime, so a single resolve up front is enough.
#
# Idempotent: peers already pinned are skipped, so re-runs (e.g. on
# container restart, where Docker regenerates /etc/hosts) just no-op.
#
# Wired into each container's start sequence as an exec wrapper so CMD
# overrides keep working.
#
# Redis is intentionally a peer here: the *server*'s sshd resolves `redis`
# for the LocalForward target, so it benefits from a pin. The redis
# container itself doesn't run this script.

set -eu

PEERS="attacker client server redis"
SELF="$(hostname)"

for peer in $PEERS; do
    [ "$peer" = "$SELF" ] && continue

    # Match "<ip> <hostname>" with whitespace boundaries so e.g. "server"
    # doesn't match "server-root".
    if grep -qE "^[0-9.]+[[:space:]]+${peer}([[:space:]]|\$)" /etc/hosts; then
        continue
    fi

    ip=""
    attempt=1
    while [ "$attempt" -le 30 ]; do
        ip=$(getent ahostsv4 "$peer" 2>/dev/null | awk 'NR==1 {print $1}')
        if [ -n "$ip" ]; then
            echo "$ip $peer" >> /etc/hosts
            echo "[pin-hosts] pinned $peer -> $ip" >&2
            break
        fi
        sleep 1
        attempt=$((attempt + 1))
    done

    if [ -z "$ip" ]; then
        echo "[pin-hosts] WARN: could not resolve $peer after 30 tries" >&2
    fi
done

exec "$@"
