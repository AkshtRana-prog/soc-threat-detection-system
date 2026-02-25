import os
import time


def read_static_logs(file_path):
    """
    Reads entire log file at once (for historical analysis).
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Log file not found: {file_path}")

    with open(file_path, "r") as f:
        return f.readlines()


def read_live_logs(file_path):
    """
    Continuously monitors a log file like 'tail -f'.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Log file not found: {file_path}")

    with open(file_path, "r") as f:
        f.seek(0, os.SEEK_END)  # Move to end of file

        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            yield line
