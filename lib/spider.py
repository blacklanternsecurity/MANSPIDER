import re
import sys
import queue
import threading
from time import sleep
import multiprocessing
from pathlib import Path
from .spiderling import *

# set up logging
log = logging.getLogger('manspider')


class FileExtensions:
    '''
    defines which file extensions get searched by default
    can be overridden with the "file_extensions" argument
    NOTE: unknown filetypes will be parsed with the "plain" method
    '''

    # parsed using the textract library
    textract = [
        '.doc',
        '.docx',
        '.xls',
        '.xlsx',
        '.ppt',
        '.pptx',
        '.pdf',
        '.eml',
    ]

    # parsed using simple file/string operations
    plain = [
        '.ps1'
        '.vbs',
        '.com',
        '.bat',
        '.txt',
        '.json',
        '.xml',
        '.ini',
        '.conf',
        '.config'
    ]

    def update(self, file_extensions):
        '''
        Replace default extension lists with user-requested ones
        '''

        new_textract = set()
        new_plain = set()

        for extension in file_extensions:
            if extension in self.textract:
                new_textract.add(extension)
            else:
                new_plain.add(extension)

        self.textract = list(new_textract)
        self.plain = list(new_plain)


    def __iter__(self):

        for e in self.textract + self.plain:
            yield e


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

        self.no_download        = options.no_download
        self.search_loot        = (True if options.targets == ['loot'] else False)

        self.init_file_extensions(options.extensions)
        self.init_filename_filters(options.filenames)
        self.init_file_content_filters(options.content)

        self.failed_logons = 0

        if self.threads == 1:
            self.spiderling_queue = queue.Queue()
        else:
            self.spiderling_pool = [None] * self.threads
            self.spiderling_queue = multiprocessing.Queue()

        # prevents needing to continually instantiate new SMBClients
        # {target: SMBClient() ...}
        self.smb_client_cache = dict()

        # directory to store documents when searching contents
        self.tmp_dir = Path('/tmp/manspider')
        self.tmp_dir.mkdir(exist_ok=True)

        # directory to store matching documents
        self.loot_dir = Path(__file__).parent.parent / 'loot'
        self.loot_dir.mkdir(exist_ok=True)


    def start(self):

        # do it the simple way if we're only using one thread
        if self.threads == 1:
            for target in self.targets:
                if not self.lockout_threshold():
                    # target, username, password, domain, hash, filename_filters, parent_queue
                    spiderling = threading.Thread(
                        target=Spiderling,
                        args=(target, self)
                    )
                    spiderling.start()

                    while 1:
                        self.check_spiderling_queue()
                        if not spiderling.is_alive():
                            break

        # otherwise, use multiprocessing
        else:
            for target in self.targets:
                while not self.lockout_threshold():
                    try:
                        for i, process in enumerate(self.spiderling_pool):
                            # if there's room in the pool
                            if process is None or not process.is_alive():
                                # start spiderling
                                self.spiderling_pool[i] = multiprocessing.Process(
                                    target=Spiderling, args=(target, self), daemon=True
                                )
                                self.spiderling_pool[i].start()
                                # break out of infinite loop
                                assert False
                            else:
                                # otherwise, clear the queue
                                self.check_spiderling_queue()

                    except AssertionError:
                        break

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
            extensions_str = '"' + '", "'.join(list(self.file_extensions)) + '"'
            log.info(f'Searching by file extension: {extensions_str}')


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
                if not f.startswith('^'):
                    regex_str = rf'.*{regex_str}'
                if not f.endswith('$'):
                    regex_str = rf'{regex_str}.*'
                self.filename_filters.append(re.compile(regex_str, re.I))
            except re.error as e:
                log.error(f'Unsupported filename regex "{f}": {e}')
                sleep(1)
        if self.filename_filters:
            filename_filter_str = '"' + '", "'.join([f.pattern for f in self.filename_filters]) + '"'
            log.info(f'Searching by filename: {filename_filter_str}')


    def init_file_content_filters(self, file_content):
        '''
        Get ready to search by file content
        '''

        # strings to look for in file content
        # if empty, content is ignored
        self.file_content_filters = []
        for f in file_content:
            try:
                self.file_content_filters.append(re.compile(f, re.I))
            except re.error as e:
                log.error(f'Unsupported file content regex "{f}": {e}')
                sleep(1)
        if self.file_content_filters:
            content_filter_str = '"' + '", "'.join([f.pattern for f in self.file_content_filters]) + '"'
            log.info(f'Searching by file content: {content_filter_str}')


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
            log.warning(f'{message.target}: {message.content}')
            self.failed_logons += 1


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