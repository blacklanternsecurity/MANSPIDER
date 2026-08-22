import os
import sys
import json
import logging
from copy import copy
from sys import stdout
from pathlib import Path
from datetime import datetime
from multiprocessing import Queue
from logging.handlers import QueueHandler, QueueListener


### JSON LINES OUTPUT ###

# JSONL destination, configured once via set_json_output() before forking so that
# child/worker processes inherit it (we force the "fork" start method).
_json_output_path = None  # file path, when writing JSONL to a file
_json_to_stdout = False  # when True, JSONL goes to stdout and logs go to stderr


def set_json_output(path):
    """
    Configure JSONL output. "path" is:
      - None / ""   -> disabled
      - "-"         -> write JSONL to stdout, and redirect human-readable logs to stderr
      - <filename>  -> append JSONL to that file
    """
    global _json_output_path, _json_to_stdout
    if not path:
        _json_output_path = None
        _json_to_stdout = False
    elif path == "-":
        _json_output_path = None
        _json_to_stdout = True
        # keep stdout clean for JSONL: send all log records to stderr instead
        console.setStream(sys.stderr)
    else:
        _json_output_path = str(path)
        _json_to_stdout = False


def json_log(record):
    """
    Emit a single record as one JSON line. No-op when --json wasn't specified.
    Safe across processes: a short write() to an O_APPEND file, or a single
    os.write() to stdout, is atomic on POSIX.
    """
    if not (_json_output_path or _json_to_stdout):
        return
    try:
        line = json.dumps(record, default=str) + "\n"
        if _json_to_stdout:
            os.write(1, line.encode("utf-8"))
        else:
            with open(_json_output_path, "a", encoding="utf-8") as f:
                f.write(line)
    except Exception:
        pass


### PRETTY COLORS ###


class ColoredFormatter(logging.Formatter):
    color_mapping = {
        "DEBUG": 69,  # blue
        "INFO": 118,  # green
        "WARNING": 208,  # orange
        "ERROR": 196,  # red
        "CRITICAL": 196,  # red
    }

    char_mapping = {
        "DEBUG": "*",
        "INFO": "+",
        "WARNING": "-",
        "ERROR": "!",
        "CRITICAL": "!!!",
    }

    prefix = "\033[1;38;5;"
    suffix = "\033[0m"

    def __init__(self, pattern):

        super().__init__(pattern)

    def format(self, record):

        colored_record = copy(record)
        levelname = colored_record.levelname
        levelchar = self.char_mapping.get(levelname, "+")
        seq = self.color_mapping.get(levelname, 15)  # default white
        colored_levelname = f"{self.prefix}{seq}m[{levelchar}]{self.suffix}"
        colored_record.levelname = colored_levelname

        return logging.Formatter.format(self, colored_record)

    @classmethod
    def green(cls, s):

        return cls.color(s)

    @classmethod
    def red(cls, s):

        return cls.color(s, level="ERROR")

    @classmethod
    def color(cls, s, level="INFO"):

        color = cls.color_mapping.get(level)
        return f"{cls.prefix}{color}m{s}{cls.suffix}"


class CustomQueueListener(QueueListener):
    """
    Ignore errors in the monitor thread that result from a race condition when the program exits
    """

    def _monitor(self):
        try:
            super()._monitor()
        except Exception:
            pass


### LOG TO STDERR ###

console = logging.StreamHandler(stdout)
# tell the handler to use this format
console.setFormatter(ColoredFormatter("%(levelname)s %(message)s"))

### LOG TO FILE ###

log_queue = Queue()
listener = CustomQueueListener(log_queue, console)
sender = QueueHandler(log_queue)
logging.getLogger("manspider").handlers = [sender]

logdir = Path.home() / ".manspider" / "logs"
logdir.mkdir(parents=True, exist_ok=True)
logfile = f"manspider_{datetime.now().strftime('%m-%d-%Y')}.log"
handler = logging.FileHandler(str(logdir / logfile))
handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
logging.getLogger("manspider").addHandler(handler)
