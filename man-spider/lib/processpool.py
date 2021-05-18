import logging
import traceback
from time import sleep
import multiprocessing as mp
from queue import Empty, Full


# set up logging
log = logging.getLogger('manspider.processpool')



class ProcessPool:
    '''
    usage:
    with ProcessPool(2) as pool:
        for i in pool.map(target, iterable):
            yield i
    '''

    def __init__(self, processes=None, daemon=False, name=''):

        self.name = f'ProcessPool'
        if name:
            self.name += f'-{name}'

        if processes is None:
            processes = mp.cpu_count()

        self.processes = processes
        self.pool = [None] * self.processes

        self.started_counter = 0
        self.finished_counter = 0

        self.daemon = daemon

        # make the result queue
        self.result_queue = mp.Manager().Queue()


    def map(self, func, iterable, args=(), kwargs={}):

        # loop until we're out of work
        for entry in iterable:

            try:

                while 1:

                    for result in self.results:
                        yield result

                    # start processes
                    for i in range(len(self.pool)):
                        process = self.pool[i]
                        if process is None or not process.is_alive():
                            self.pool[i] = mp.Process(target=self.execute, args=(func, self.result_queue, (entry,)+args), \
                                kwargs=kwargs, daemon=self.daemon)
                            self.pool[i].start()
                            self.started_counter += 1
                            log.debug(f'{self.name}: {self.started_counter:,} processes started')
                            # success, move on to next
                            assert False

                        for result in self.results:
                            yield result

                    # prevent unnecessary CPU usage
                    sleep(.1)

            except AssertionError:
                continue

        # wait for processes to finish
        while 1:

            finished_threads = [p is None or not p.is_alive() for p in self.pool]
            if all(finished_threads):
                self.finished_counter += len([p for p in self.pool if p is not None and not p.is_alive()])
                break
            else:
                log.debug(f'{self.name}: Waiting for {finished_threads.count(False):,} threads to finish')
                sleep(1)

        for result in self.results:
            yield result


    @property
    def results(self):

        while 1:
            try:
                result = self.result_queue.get_nowait()
                self.finished_counter += 1
                log.debug(f'{self.name}: {self.finished_counter:,} processes finished')
                yield result
            except Empty:
                sleep(.1)
                break


    @staticmethod
    def execute(func, result_queue, args=(), kwargs={}):
        '''
        Executes given function and places return value in result queue
        '''

        try:
            result_queue.put(func(*args, **kwargs))
        except Exception as e:
            if type(e) not in [FileNotFoundError]:
                log.critical(format_exc())
        except KeyboardInterrupt as e:
            log.critical('ProcessPool Interrupted')


    @staticmethod
    def _close_queue(q):

        while 1:
            try:
                q.get_nowait()
            except Empty:
                break
        q.close()


    def __enter__(self):

        return self


    def __exit__(self, exception_type, exception_value, traceback):

        try:
            self._close_queue(self.result_queue)
        except Exception:
            pass