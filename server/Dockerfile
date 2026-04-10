FROM python:3.14-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates patch \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --------------------------------------------------------------------------
# RFC 4253 §6.2 compliance patch for AsyncSSH
# --------------------------------------------------------------------------
# Replace asyncssh.compression._ZLibCompress's Z_SYNC_FLUSH with the
# RFC-mandated Z_PARTIAL_FLUSH so the in-process compressor wire format
# matches a spec-compliant SSH implementation (which is what OpenSSH's
# bundled zlib wrapper does).  Applied at image build time so there is
# no runtime monkey-patching.
COPY patches/asyncssh-rfc4253-partial-flush.patch /tmp/
RUN set -eux; \
    SITE_PACKAGES=$(python -c 'import asyncssh, os; print(os.path.dirname(asyncssh.__file__))'); \
    cd "$SITE_PACKAGES/.."; \
    patch -p1 --no-backup-if-mismatch --verbose < /tmp/asyncssh-rfc4253-partial-flush.patch; \
    # Verify the actual flush() call was switched.  We grep for the
    # exact call site, not the symbol name (the patched docstring
    # still mentions Z_SYNC_FLUSH for context).
    grep -q 'flush(zlib.Z_PARTIAL_FLUSH)' "$SITE_PACKAGES/compression.py" \
        || { echo "FAIL: patch did not insert Z_PARTIAL_FLUSH call"; exit 1; }; \
    if grep -q 'flush(zlib.Z_SYNC_FLUSH)' "$SITE_PACKAGES/compression.py"; then \
        echo "FAIL: asyncssh/compression.py still has flush(zlib.Z_SYNC_FLUSH)"; \
        exit 1; \
    fi; \
    rm /tmp/asyncssh-rfc4253-partial-flush.patch

COPY server/server.py .

CMD ["python", "/app/server.py"]
