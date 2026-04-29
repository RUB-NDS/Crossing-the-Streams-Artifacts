"""Placeholder for the engine HTTP service. Replaced by Task 12.

Keeps PID alive so the server container's entrypoint can `exec su` to
this without immediate exit, which would take sshd down with it.
"""
import time

if __name__ == "__main__":
    print("attacker.service placeholder — replaced in Task 12", flush=True)
    while True:
        time.sleep(3600)
