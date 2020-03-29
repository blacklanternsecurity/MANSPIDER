import logging
import textract
from .smb import *
from .file import *
from .util import *
from .errors import *
from shutil import move
import subprocess as sp
from pathlib import Path
from zipfile import BadZipFile # an unhandled textract error
from traceback import format_exc
from .logger import ColoredFormatter


log = logging.getLogger('manspider.spiderling')


class SpiderlingMessage:
    '''
    Message which gets sent back to the parent through parent_queue
    '''

    def __init__(self, message_type, target, content):
        '''
        "message_type" is a string, and can be:
            "e" - error
            "a" - authentication failure
        '''
        self.type = message_type
        self.target = target
        self.content = content



class Spiderling:
    '''
    Enumerates SMB shares and spiders all possible directories/filenames up to maxdepth
    Designed to be threadable
    '''

    def __init__(self, target, parent):

        # ignore keyboardinterrupt
        if parent.threads > 1:
            import signal
            signal.signal(signal.SIGINT, signal.SIG_IGN)

            self.parent = parent
            self.target = target

        # unless we're only searching local files, connect to target
        if self.target == 'loot':
            self.go()

        else:
            try:
                
                self.smb_client = SMBClient(
                    target,
                    parent.username,
                    parent.password,
                    parent.domain,
                    parent.nthash,
                )

                logon_result = self.smb_client.login()
                if logon_result not in [True, None]:
                    self.message_parent('a', logon_result)

                if logon_result is not None:
                    self.go()

            # send all exceptions to the parent
            except Exception as e:
                if log.level <= logging.DEBUG:
                    log.error(format_exc())
                else:
                    log.error(f'Error in spiderling: {e}')


    def go(self):
        '''
        go spider go spider go
        '''

        if self.target == 'loot':
            self.parse_local_files()

        else:
            for share in self.shares:
                for file in self.list_files(share):
                    # if file content search is enabled

                    try:
                        log.info(f'{file} ({bytes_to_human(file.size)})')
                    except FileRetrievalError as e:
                        log.debug(e)
                    if self.parent.file_content_filters:
                        self.parse_file(file)
                    else:
                        self.message_parent('f', content=file)


    @property
    def shares(self):
        '''
        Lists all shares on single target
        '''

        for share in self.smb_client.shares:
            # if the share has been whitelisted
            if ((not self.parent.share_whitelist) or (share.lower() in self.parent.share_whitelist)):
                # and hasn't been blacklisted
                if ((not self.parent.share_blacklist) or (share.lower() not in self.parent.share_blacklist)):
                    yield share
                else:
                    log.debug(f'{self.target}: Skipping blacklisted share "{share}"')
            else:
                log.debug(f'{self.target}: Skipping share "{share}", not in whitelist')


    def list_files(self, share, path='', depth=0, tries=2):
        '''
        Lists files inside a specific directory
        @byt3bl33d3r it's really not *that* funky
        '''

        if depth < self.parent.maxdepth:

            files = []
            while tries > 0:
                try:
                    files = list(self.smb_client.ls(share, path))
                    break
                except FileListError as e:
                    if 'ACCESS_DENIED' in str(e):
                        log.debug(f'{self.target}: Error listing files: {e}')
                        break
                    else:
                        tries -= 1

            if files:
                log.debug(f'{self.target}: {share}{path}: contains {len(files):,} items')

            for f in files:
                name = f.get_longname()
                full_path = f'{path}\\{name}'
                # if it's a directory, go deeper
                if f.is_directory():
                    for file in self.list_files(share, full_path, (depth+1)):
                        yield file

                # otherwise, if filename matches filters
                elif self.filename_match(name):

                    # and if it matches extension filters
                    if self.extension_match(name):

                        try:
                            filesize = f.get_filesize()
                        except Exception as e:
                            handle_impacket_error(e)
                            continue

                        # and if it's a non-empty file that's smaller than the size limit'
                        if filesize > 0 and filesize < self.parent.max_filesize:
                            full_path_fixed = full_path.lstrip('\\')
                            remote_file = RemoteFile(full_path_fixed, share, self.target, size=filesize)

                            # download the file if content searching is disabled
                            if not self.parent.file_content_filters and not self.parent.no_download:
                                smb_client = self.parent.get_smb_client(self.target)
                                try:
                                    remote_file.get(smb_client)
                                    self.save_file(remote_file)
                                except FileRetrievalError as e:
                                    log.debug(f'{self.target}: {e}')

                            yield remote_file



    def filename_match(self, filename):
        '''
        Return true if "filename" matches any of the filename filters
        '''

        if not self.parent.filename_filters:
            return True
        if any([f_regex.match(filename) for f_regex in self.parent.filename_filters]):
            return True
        return False


    def extension_match(self, filename):
        '''
        Return true if "filename" matches any of the extension filters
        '''

        file_extension_filters = list(self.parent.file_extensions)

        if not file_extension_filters:
            return True

        # .tar.gz will match both ".gz" and ".tar.gz"
        extension = ''.join(Path(filename).suffixes).lower()

        if any([extension.endswith(e) for e in file_extension_filters]):
            return True

        return False



    def file_content_match(self, file_content):
        '''
        Finds all regex matches in file content
        '''

        for _filter in self.parent.file_content_filters:
            for match in _filter.finditer(file_content):
                # ( filter, (match_start_index, match_end_index) )
                yield (_filter, match.span())


    def message_parent(self, message_type, content=''):
        '''
        Send a message to the parent spider
        '''

        self.parent.spiderling_queue.put(
            SpiderlingMessage(message_type, self.target, content)
        )


    def grep(self, content, pattern):

        if not self.parent.quiet:
            try:
                '''
                GREP(1)
                    -m NUM, --max-count=NUM
                        Stop  reading  a file after NUM matching lines
                    -i, --ignore-case
                        Ignore case distinctions
                    -a, --text
                        Process a binary file as if it were text
                '''
                grep_process = sp.Popen(
                    ['egrep', '-iam', '5', '--color=always', pattern],
                    stdin=sp.PIPE,
                    stdout=sp.PIPE
                )
                grep_output = grep_process.communicate(content)[0]
                for line in grep_output.splitlines():
                    try:
                        log.info(line.decode()[:150])
                    except UnicodeDecodeError:
                        log.info(str(line)[:150])
            except (sp.SubprocessError, OSError, IndexError):
                pass


    def parse_file(self, remote_file):
        '''
        Parse a file on a remote share
        '''
    
        suffix = Path(str(remote_file)).suffix.lower()

        if suffix in self.parent.file_extensions.textract:

            smb_client = self.parent.get_smb_client(self.target)

            try:
                remote_file.get(smb_client)
                matches = self.parse_local_file(str(remote_file.tmp_filename), str(remote_file))

                if matches and not self.parent.no_download:
                    self.save_file(remote_file)
                else:
                    remote_file.tmp_filename.unlink()

            except FileRetrievalError as e:
                log.debug(f'{self.target}: {e}')


    def parse_local_file(self, local_file, pretty_filename=None):
        '''
        Parse a file on the local filesystem
        '''

        matches = dict()

        if pretty_filename is None:
            pretty_filename = str(local_file)

        try:

            binary_content = textract.process(str(local_file), encoding='utf-8')
            text_content = better_decode(binary_content)

            for _filter, match in self.file_content_match(text_content):
                try:
                    matches[_filter] += 1
                except KeyError:
                    matches[_filter] = 1

            for _filter, match_count in matches.items():
                log.info(f'{pretty_filename}: matched "{_filter.pattern}" {match_count:,} times')
                if not self.parent.quiet:
                    #log.info('=' * 80)
                    self.grep(binary_content, _filter.pattern)
                    #log.info('=' * 80)

        except (UnicodeDecodeError, BadZipFile, textract.exceptions.CommandLineError) as e:
            log.debug(f'{self.target}: Error extracting text from {pretty_filename}: {e}')

        return matches


    def parse_local_files(self):

        for file in list(list_files(self.parent.loot_dir)):
            if self.extension_match(file) and self.filename_match(file):
                shortened_file = f'./loot/{file.relative_to(self.parent.loot_dir)}'
                log.info(f'Found file: {shortened_file}')
                self.parse_local_file(file, shortened_file)
            else:
                log.debug(f'File {file} does not match filters, skipping')



    def save_file(self, remote_file):
        '''
        Moves a file from temp storage into the loot directory
        '''

        # replace backslashes with underscores to preserve directory names
        loot_filename = str(remote_file).replace('\\', '_')
        loot_dest = self.parent.loot_dir / loot_filename
        move(str(remote_file.tmp_filename), str(loot_dest))