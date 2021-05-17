import logging
from copy import copy
from sys import stdout
from pathlib import Path
from datetime import datetime
from multiprocessing import Queue
from logging.handlers import QueueHandler, QueueListener


### PRETTY COLORS ###


class ColoredFormatter(logging.Formatter):

    color_mapping = {
        'DEBUG':    69, # blue
        'INFO':     118, # green
        'WARNING':  208, # orange
        'ERROR':    196, # red
        'CRITICAL': 196, # red
    }

    char_mapping = {
        'DEBUG':    '*',
        'INFO':     '+',
        'WARNING':  '-',
        'ERROR':    '!',
        'CRITICAL': '!!!',
    }

    prefix = '\033[1;38;5;'
    suffix = '\033[0m'

    def __init__(self, pattern):

        super().__init__(pattern)


    def format(self, record):

        colored_record = copy(record)
        levelname = colored_record.levelname
        levelchar = self.char_mapping.get(levelname, '+')
        seq = self.color_mapping.get(levelname, 15) # default white
        colored_levelname = f'{self.prefix}{seq}m[{levelchar}]{self.suffix}'
        colored_record.levelname = colored_levelname

        return logging.Formatter.format(self, colored_record)


    @classmethod
    def green(cls, s):

        return cls.color(s)


    @classmethod
    def red(cls, s):

        return cls.color(s, level='ERROR')


    @classmethod
    def color(cls, s, level='INFO'):

        color = cls.color_mapping.get(level)
        return f'{cls.prefix}{color}m{s}{cls.suffix}'



class CustomQueueListener(QueueListener):
    '''
    Ignore errors in the monitor thread that result from a race condition when the program exits
    '''
    def _monitor(self):
        try:
            super()._monitor()
        except Exception:
            pass


### LOG TO STDERR ###

console = logging.StreamHandler(stdout)
# tell the handler to use this format
console.setFormatter(ColoredFormatter('%(levelname)s %(message)s'))

### LOG TO FILE ###

log_queue = Queue()
listener = CustomQueueListener(log_queue, console)
sender = QueueHandler(log_queue)
logging.getLogger('manspider').handlers = [sender]

logdir = Path.home() / '.manspider' / 'logs'
logdir.mkdir(parents=True, exist_ok=True)
logfile = f'manspider_{datetime.now().strftime("%m-%d-%Y")}.log'
handler = logging.FileHandler(str(logdir / logfile))
handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
logging.getLogger('manspider').addHandler(handler)