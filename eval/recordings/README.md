# Recordings

Answers a live model gave, kept so that the responder's `replay` backend can give them again
without a model (phase 3 spec 3.2b). `make llm-record` writes them; each file is named by a
hash of the whole request the model was sent (the fixed part, the session's state, the
command, the sampling settings), so a recording answers that request and no other.

CI and the unit tests use `replay` only. A request with no recording here is an `abort`, and
the decoy answers as its emulator would.
