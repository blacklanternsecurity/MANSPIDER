import string
import logging
import pathlib
from .smb import *
from .file import *
from .util import *
from .errors import *
import multiprocessing
from shutil import move
from .processpool import *
from traceback import format_exc


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

    # these extensions don't get parsed for content, unless explicitly specified
    dont_parse = [
        '.png',
        '.gif',
        '.tiff',
        '.msi',
        '.bmp',
        '.jpg',
        '.jpeg',
        '.zip',
        '.gz',
        '.bz2',
        '.7z',
        '.xz',
    ]

    def __init__(self, target, parent):

        try:

            self.parent = parent
            self.target = target

            # unless we're only searching local files, connect to target
            if type(self.target) == pathlib.PosixPath:
                self.local = True
                self.go()

            else:
                self.local = False

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

            # file parsing parallelized one process at a time
            # allows file to be parsed while next one is being fetched
            self.parser_process = None

        except KeyboardInterrupt:
            log.critical('Spiderling Interrupted')

        # log all exceptions
        except Exception as e:
            if log.level <= logging.DEBUG:
                log.error(format_exc())
            else:
                log.error(f'Error in spiderling: {e}')


    def go(self):
        '''
        go spider go spider go
        '''

        # local files
        if self.local:
            if self.parent.parser.content_filters:
                self.parse_local_files(self.files)
            else:
                # just list the files
                list(self.files)

        else:
            # remote files
            for file in self.files:

                # if content searching is enabled, parse the file
                if self.parent.parser.content_filters:
                    try:
                        self.parser_process.join()
                    except AttributeError:
                        pass
                    self.parser_process = multiprocessing.Process(target=self.parse_file, args=(file,))
                    self.parser_process.start()

                # otherwise, just save it
                elif not self.local:
                    log.info(f'{self.target}: {file.share}\\{file.name} ({bytes_to_human(file.size)})')
                    if not self.parent.no_download:
                        self.save_file(file)

        log.info(f'Finished spidering {self.target}')



    @property
    def files(self):
        '''
        Yields all files on the target to be parsed/downloaded
        Premptively download matching files into temp directory
        '''

        if self.local:
            for file in list(list_files(self.target)):
                if self.extension_blacklisted(file):
                    log.debug(f'{self.target}: Skipping {file}: extension is blacklisted')
                    continue
                if self.path_match(file) or (self.parent.or_logic and self.parent.parser.content_filters):
                    if self.path_match(file):
                        log.debug(pathlib.Path(file).relative_to(self.target))
                    if not self.is_binary_file(file):
                        yield file
                else:
                    log.debug(f'Skipping {file}: does not match filename/extension filters')

        else:
            for share in self.shares:
                for remote_file in self.list_files(share):
                    if not self.parent.no_download or self.parent.parser.content_filters:
                        self.get_file(remote_file)
                    yield remote_file



    def parse_file(self, file):
        '''
        Simple wrapper around self.parent.parser.parse_file()
        For sole purpose of threading
        '''

        try:

            if type(file) == RemoteFile:
                matches = self.parent.parser.parse_file(str(file.tmp_filename), pretty_filename=str(file))
                if matches and not self.parent.no_download:
                    self.save_file(file)
                else:
                    file.tmp_filename.unlink()

            else:
                log.debug(f'Found file: {file}')
                self.parent.parser.parse_file(file, file)

        # log all exceptions
        except Exception as e:
            if log.level <= logging.DEBUG:
                log.error(format_exc())
            else:
                log.error(f'Error parsing file {file}: {e}')

        except KeyboardInterrupt:
            log.critical('File parsing interrupted')


    @property
    def shares(self):
        '''
        Lists all shares on single target
        '''

        for share in self.smb_client.shares:
            if self.share_match(share):
                yield share



    def list_files(self, share, path='', depth=0, tries=2):
        '''
        List files inside a specific directory
        Only yield files which conform to all filters (except content)
        '''

        if depth < self.parent.maxdepth and self.dir_match(path):

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

                else:

                    # skip the file if it didn't match extension filters
                    if self.extension_blacklisted(name):
                        log.debug(f'{self.target}: Skipping {share}{full_path}: extension is blacklisted')
                        continue

                    if not self.path_match(name):
                        if not (
                                # all of these have to be true in order to get past this point
                                # "or logic" is enabled
                                self.parent.or_logic and
                                # and file does not have a "don't parse" extension
                                (not self.is_binary_file(name)) and
                                # and content filters are enabled
                                self.parent.parser.content_filters
                            ):
                            log.debug(f'{self.target}: Skipping {share}{full_path}: filename/extensions do not match')
                            continue

                    # try to get the size of the file
                    try:
                        filesize = f.get_filesize()
                    except Exception as e:
                        handle_impacket_error(e)
                        continue

                    # make the RemoteFile object (the file won't be read yet)
                    full_path_fixed = full_path.lstrip('\\')
                    remote_file = RemoteFile(full_path_fixed, share, self.target, size=filesize)

                    # if it's a non-empty file that's smaller than the size limit
                    if filesize > 0 and filesize < self.parent.max_filesize:

                        # if it matched filename/extension filters and we're downloading files
                        if (self.parent.file_extensions or self.parent.filename_filters) and not self.parent.no_download:
                            # but the extension is marked as "don't parse"
                            if self.is_binary_file(name):
                                # don't parse it, instead save it and continue
                                log.info(f'{self.target}: {remote_file.share}\\{remote_file.name}')
                                if self.get_file(remote_file):
                                    self.save_file(remote_file)
                                    continue

                        # file is ready to be parsed
                        yield remote_file

                    else:
                        log.debug(f'{self.target}: {full_path} is either empty or too large')


    def path_match(self, file):
        '''
        Based on whether "or" logic is enabled, return True or False
        if the filename + extension meets the requirements
        '''
        filename_match = self.filename_match(file)
        extension_match = self.extension_whitelisted(file)
        if self.parent.or_logic:
            return (filename_match and self.parent.filename_filters) or (extension_match and self.parent.file_extensions)
        else:
            return filename_match and extension_match



    def share_match(self, share):
        '''
        Return true if "share" matches any of the share filters
        '''

        # if the share has been whitelisted
        if ((not self.parent.share_whitelist) or (share.lower() in self.parent.share_whitelist)):
            # and hasn't been blacklisted
            if ((not self.parent.share_blacklist) or (share.lower() not in self.parent.share_blacklist)):
                return True
            else:
                log.debug(f'{self.target}: Skipping blacklisted share: {share}')
        else:
            log.debug(f'{self.target}: Skipping share {share}: not in whitelist')

        return False


    def dir_match(self, path):
        '''
        Return true if "path" matches any of the directory filters
        '''

        # convert forward slashes to backwards
        dirname = str(path).lower().replace('/', '\\')

        # root path always passes
        if not path:
            return True

        # if whitelist check passes
        if (not self.parent.dir_whitelist) or any([k.lower() in dirname for k in self.parent.dir_whitelist]):
            # and blacklist check passes
            if (not self.parent.dir_blacklist) or not any([k.lower() in dirname for k in self.parent.dir_blacklist]):
                return True
            else:
                log.debug(f'{self.target}: Skipping blacklisted dir: {path}')
        else:
            log.debug(f'{self.target}: Skipping dir {path}: not in whitelist')

        return False


    def filename_match(self, filename):
        '''
        Return true if "filename" matches any of the filename filters
        '''

        if (not self.parent.filename_filters) or any([f_regex.match(str(pathlib.Path(filename).stem)) for f_regex in self.parent.filename_filters]):
            return True
        else:
            log.debug(f'{self.target}: {filename} does not match filename filters')

        return False


    def is_binary_file(self, filename):
        '''
        Returns true if file is a bad extension type, e.g. encrypted or compressed
        '''

        extension = ''.join(pathlib.Path(filename).suffixes).lower()
        if any([extension.endswith(e.lower()) for e in self.dont_parse]):
            if extension not in self.parent.file_extensions:
                log.debug(f'{self.target}: Not parsing {filename} due to undesirable extension')
                return True
        return False


    def extension_blacklisted(self, filename):
        '''
        Return True if folder, file name, or extension has been blacklisted
        '''
        extension = ''.join(pathlib.Path(filename).suffixes).lower()
        excluded_extensions = list(self.parent.extension_blacklist)

        if not excluded_extensions:
            return False

        if not any([extension.endswith(e) for e in excluded_extensions]):
            return False
        else:
            log.debug(f'{self.target}: Skipping file with blacklisted extension: {filename}')
            return True


    def extension_whitelisted(self, filename):
        '''
        Return True if file extension has been whitelisted
        '''
        # a .tar.gz file will match both filters ".gz" and ".tar.gz"
        extension = ''.join(pathlib.Path(filename).suffixes).lower()
        extensions = list(self.parent.file_extensions)

        if not extensions:
            return True

        # if whitelist check passes
        if  any([(extension.endswith(e) if e else extension == e) for e in extensions]):
            log.debug(f'{self.target}: {filename} matches extension filters')
            return True
        else:
            log.debug(f'{self.target}: Skipping file {filename}, does not match extension filters')
            return False


    def message_parent(self, message_type, content=''):
        '''
        Send a message to the parent spider
        '''

        self.parent.spiderling_queue.put(
            SpiderlingMessage(message_type, self.target, content)
        )


    def parse_local_files(self, files):

        with ProcessPool(self.parent.threads) as pool:
            for r in pool.map(self.parse_file, files):
                pass


    def save_file(self, remote_file):
        '''
        Moves a file from temp storage into the loot directory
        '''

        allowed_chars = string.ascii_lowercase + string.ascii_uppercase + string.digits + '._ '

        # replace backslashes with underscores to preserve directory names
        loot_filename = str(remote_file).replace('\\', '_')
        # remove weird characters
        loot_filename = ''.join([c for c in loot_filename if c in allowed_chars])
        loot_dest = self.parent.loot_dir / loot_filename
        try:
            move(str(remote_file.tmp_filename), str(loot_dest))
        except Exception:
            log.warning(f'Error saving {remote_file}')


    def get_file(self, remote_file):
        '''
        Attempts to retrieve "remote_file" from share and returns True if successful
        '''

        try:
            smb_client = self.parent.get_smb_client(self.target)
            log.debug(f'{self.target}: Downloading {remote_file.share}\\{remote_file.name}')
            remote_file.get(smb_client)
            return True
        except FileRetrievalError as e:
            log.debug(f'{self.target}: {e}')

        return False

