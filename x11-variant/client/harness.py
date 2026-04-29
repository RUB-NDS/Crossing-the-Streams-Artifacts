"""Placeholder for the harness module. Replaced by Tasks 10–11.

Keeps PID alive so the client container's entrypoint can `exec su` to
this without immediate exit.
"""
import time

if __name__ == "__main__":
    print("harness placeholder — replaced in Tasks 10–11", flush=True)
    while True:
        time.sleep(3600)
