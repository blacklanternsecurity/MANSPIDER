#!/bin/bash
# By default, run the published image -- fast, no Docker build tooling or
# local source checkout required. Set MANSPIDER_LOCAL_BUILD=1 to instead
# build from this checkout's source, e.g. when testing local patches to
# man_spider/ before they're released.
IMAGE="blacklanternsecurity/manspider"

if [[ "${MANSPIDER_LOCAL_BUILD:-}" == "1" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"

    # Sanity check: refuse to build from the wrong directory (e.g. if this file
    # was somehow sourced/invoked in a way that broke path resolution) instead
    # of silently sending some other directory as the Docker build context.
    if [[ ! -f "$SCRIPT_DIR/Dockerfile" ]]; then
        echo "ERROR: resolved SCRIPT_DIR=\"$SCRIPT_DIR\" has no Dockerfile -- refusing to build." >&2
        exit 1
    fi
    docker build -q -t blacklanternsecurity/manspider-local "$SCRIPT_DIR" >/dev/null
    IMAGE="blacklanternsecurity/manspider-local"
fi

# Resolve the REAL invoking user's home dir, not root's -- $HOME is /root
# under sudo by default (env_reset), but SUDO_USER always survives it.
REAL_HOME="$(getent passwd "${SUDO_USER:-$USER}" | cut -d: -f6)"

# Mounts cwd (so relative target-list files resolve inside the container),
# the real home dir read-only at the SAME path (so absolute /home/<you>/...
# target-file/ccache paths just work, without needing to copy anything into
# cwd first), loot/logs dirs, and (as a fallback) the Kerberos ccache +
# krb5.conf if KRB5CCNAME is set on the host.
#
# Simplest option for Kerberos: since your home dir is now mounted, just
# pass the ccache path straight through with `-K <file>` on the manspider
# command line -- this also sidesteps sudo stripping KRB5CCNAME entirely.
docker run --rm \
    --entrypoint /manspider/.venv/bin/manspider \
    -v ./loot:/root/.manspider/loot \
    -v ./logs:/root/.manspider/logs \
    -v "$(pwd)":/work -w /work \
    ${REAL_HOME:+-v "$REAL_HOME":"$REAL_HOME":ro} \
    ${KRB5CCNAME:+-e KRB5CCNAME=/tmp/krb5cc -v "${KRB5CCNAME#FILE:}":/tmp/krb5cc} \
    $(test -f /etc/krb5.conf && echo -v /etc/krb5.conf:/etc/krb5.conf:ro) \
    "$IMAGE" "$@"
