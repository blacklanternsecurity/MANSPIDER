import re
import sys
import queue
import threading
from time import sleep
import multiprocessing
from pathlib import Path
from .spiderling import *
from .parser import FileParser

# set up logging
log = logging.getLogger('manspider')


class MANSPIDER:

    def __init__(self, options):

        self.targets            = options.targets
        self.threads            = options.threads
        self.maxdepth           = options.maxdepth
        self.quiet              = options.quiet

        self.username           = options.username
        self.password           = options.password
        self.domain             = options.domain
        self.nthash             = options.hash
        self.max_failed_logons  = options.max_failed_logons
        self.max_filesize       = options.max_filesize

        self.share_whitelist    = options.sharenames
        self.share_blacklist    = options.exclude_sharenames

        self.dir_whitelist      = options.dirnames
        self.dir_blacklist      = options.exclude_dirnames

        self.no_download        = options.no_download

        # applies "or" logic instead of "and"
        # e.g. file is downloaded if filename OR extension OR content match
        self.or_logic           = options.or_logic

        self.extension_blacklist= options.exclude_extensions
        self.file_extensions    = options.extensions
        if self.file_extensions:
            extensions_str = '"' + '", "'.join(list(self.file_extensions)) + '"'
            log.info(f'Searching by file extension: {extensions_str}')

        self.init_filename_filters(options.filenames)
        self.parser = FileParser(options.content, quiet=self.quiet)

        self.failed_logons = 0

        self.spiderling_pool = [None] * self.threads
        self.spiderling_queue = multiprocessing.Manager().Queue()

        # prevents needing to continually instantiate new SMBClients
        # {target: SMBClient() ...}
        self.smb_client_cache = dict()

        # directory to store documents when searching contents
        self.tmp_dir = Path('/tmp/.manspider')
        self.tmp_dir.mkdir(exist_ok=True)

        # directory to store matching documents
        self.loot_dir = Path.home() / '.manspider' / 'loot'

        if(options.loot_dir):
            self.loot_dir=Path(options.loot_dir)
        
        self.loot_dir.mkdir(parents=True, exist_ok=True)

        if not options.no_download:
            log.info(f'Matching files will be downloaded to {self.loot_dir}')


    def start(self):

        for target in self.targets:
            try:
                while 1:
                    for i, process in enumerate(self.spiderling_pool):
                        # if there's room in the pool
                        if process is None or not process.is_alive():
                            # start spiderling
                            self.spiderling_pool[i] = multiprocessing.Process(
                                target=Spiderling, args=(target, self), daemon=False
                            )
                            self.spiderling_pool[i].start()
                            # success, break out of infinite loop
                            assert False
                        else:
                            # otherwise, clear the queue
                            self.check_spiderling_queue()

            except AssertionError:
                continue

            # save on CPU
            sleep(.1)

        while 1:
            self.check_spiderling_queue()
            dead_spiderlings = [s is None or not s.is_alive() for s in self.spiderling_pool]
            if all(dead_spiderlings):
                break

        # make sure the queue is empty
        self.check_spiderling_queue()



    def init_file_extensions(self, file_extensions):
        '''
        Get ready to search by file extension
        '''

        self.file_extensions = FileExtensions()
        if file_extensions:
            self.file_extensions.update(file_extensions)
            


    def init_filename_filters(self, filename_filters):
        '''
        Get ready to search by filename
        '''

        # strings to look for in filenames
        # if empty, all filenames are matched
        self.filename_filters = []
        for f in filename_filters:
            regex_str = str(f)
            try:
                if not any([f.startswith(x) for x in ['^', '.*']]):
                    regex_str = rf'.*{regex_str}'
                if not any([f.endswith(x) for x in ['$', '.*']]):
                    regex_str = rf'{regex_str}.*'
                self.filename_filters.append(re.compile(regex_str, re.I))
            except re.error as e:
                log.error(f'Unsupported filename regex "{f}": {e}')
                sleep(1)
        if self.filename_filters:
            filename_filter_str = '"' + '", "'.join([f.pattern for f in self.filename_filters]) + '"'
            log.info(f'Searching by filename: {filename_filter_str}')


    def check_spiderling_queue(self):
        '''
        Empty the spiderling queue
        '''

        while 1:
            try:
                message = self.spiderling_queue.get_nowait()
                self.process_message(message)

            except queue.Empty:
                break


    def process_message(self, message):
        '''
        Process messages from spiderlings
        Log messages, errors, files, etc.
        '''
        if message.type == 'a':
            if message.content == False:
                self.failed_logons += 1
            if self.lockout_threshold():
                log.error(f'REACHED MAXIMUM FAILED LOGONS OF {self.max_failed_logons:,}')
                log.error('KILLING EXISTING SPIDERLINGS AND CONTINUING WITH GUEST/NULL SESSIONS')
                #for spiderling in self.spiderling_pool:
                #    spiderling.kill()
                self.username = ''
                self.password = ''
                self.nthash = ''
                self.domain = ''


    def lockout_threshold(self):
        '''
        Return True if we've reached max failed logons
        '''

        if self.max_failed_logons is not None:
            if self.failed_logons >= self.max_failed_logons and self.domain:
                return True
        return False


    def get_smb_client(self, target):
        '''
        Check if we already have an smb_client cached
        If not, then create it
        '''

        smb_client = self.smb_client_cache.get(target, None)

        if smb_client is None:
            smb_client = SMBClient(
                target,
                self.username,
                self.password,
                self.domain,
                self.nthash,
            )
            logon_result = smb_client.login()
            if logon_result == False:
                self.failed_logons += 1
            self.smb_client_cache[target] = smb_client

        return smb_client
