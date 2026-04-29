DEFAULT_TX_BYTES_PATH = "/sys/class/net/eth0/statistics/tx_bytes"


def read_tx_bytes(path: str = DEFAULT_TX_BYTES_PATH) -> int:
    with open(path, "r") as f:
        return int(f.read().strip())
