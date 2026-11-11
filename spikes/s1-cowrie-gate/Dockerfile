# Spike S1: stock Cowrie 3.1.6 image with the MIRAGE policy-gate patch applied.
# Build context: spikes/s1-cowrie-gate (needs upstream/ checked out and patched; see README).
FROM cowrie/cowrie:3.1.6
COPY upstream/src/cowrie/mirage_gate.py /cowrie/cowrie-git/src/cowrie/mirage_gate.py
COPY upstream/src/cowrie/shell/honeypot.py /cowrie/cowrie-git/src/cowrie/shell/honeypot.py
COPY upstream/src/cowrie/core/eventids.py /cowrie/cowrie-git/src/cowrie/core/eventids.py
COPY upstream/src/cowrie/shell/session.py /cowrie/cowrie-git/src/cowrie/shell/session.py
