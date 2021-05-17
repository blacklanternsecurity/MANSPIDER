import re
import magic
import logging
import textract
from ..util import *
from ..logger import *
import subprocess as sp
from ..logger import ColoredFormatter

log = logging.getLogger('manspider.parser')


class FileParser:

    # parsed using the textract library
    textract_extensions = [
        '.doc',
        '.docx',
        '.xls',
        '.xlsx',
        '.ppt',
        '.pptx',
        '.pdf',
        '.eml',
        '.png',
        '.jpg',
        '.jpeg'
    ]

    # don't parse files with these magic types
    magic_blacklist = [
        # PNG, JPEG, etc.
        # 'image data',
        # ZIP, GZ, etc.
        'archive data',
        # encrypted data
        'encrypted'
    ]


    def __init__(self, filters, quiet=False):

        self.init_content_filters(filters)
        self.quiet = quiet



    def init_content_filters(self, file_content):
        '''
        Get ready to search by file content
        '''

        # strings to look for in file content
        # if empty, content is ignored
        self.content_filters = []
        for f in file_content:
            try:
                self.content_filters.append(re.compile(f, re.I))
            except re.error as e:
                log.error(f'Unsupported file content regex "{f}": {e}')
                sleep(1)
        if self.content_filters:
            content_filter_str = '"' + '", "'.join([f.pattern for f in self.content_filters]) + '"'
            log.info(f'Searching by file content: {content_filter_str}')



    def match(self, file_content):
        '''
        Finds all regex matches in file content
        '''

        for _filter in self.content_filters:
            for match in _filter.finditer(file_content):
                # ( filter, (match_start_index, match_end_index) )
                yield (_filter, match.span())


    def match_magic(self, file):
        '''
        Returns True if the file isn't of a blacklisted file type
        '''

        # get magic type
        magic_type = magic.from_file(str(file)).lower()
        for keyword in self.magic_blacklist:
            if keyword.lower() in magic_type:
                log.debug(f'Not parsing {file}: blacklisted magic type: "{keyword}"')
                return False

        return True



    def grep(self, content, pattern):

        if not self.quiet:
            try:
                '''
                GREP(1)
                    -E, --extended-regexp
                        Interpret PATTERN as an extended regular expression
                    -i, --ignore-case
                        Ignore case distinctions
                    -a, --text
                        Process a binary file as if it were text
                    -m NUM, --max-count=NUM
                        Stop  reading  a file after NUM matching lines
                '''
                grep_process = sp.Popen(
                    ['grep', '-Eiam', '5', '--color=always', pattern],
                    stdin=sp.PIPE,
                    stdout=sp.PIPE
                )
                grep_output = grep_process.communicate(content)[0]
                for line in grep_output.splitlines():
                    log.info(better_decode(line[:500]))
            except (sp.SubprocessError, OSError, IndexError):
                pass


    def parse_file(self, file, pretty_filename=None):
        '''
        Parse a file on the local filesystem
        '''

        if pretty_filename is None:
            pretty_filename = str(file)

        log.debug(f'Parsing file: {pretty_filename}')

        matches = dict()

        try:

            matches = self.textract(file, pretty_filename=pretty_filename)

        except Exception as e:
            #except (BadZipFile, textract.exceptions.CommandLineError) as e:
            if log.level <= logging.DEBUG:
                log.warning(f'Error extracting text from {pretty_filename}: {e}')
            else:
                log.warning(f'Error extracting text from {pretty_filename} (-v to debug)')
            
        return matches


    def textract(self, file, pretty_filename):
        '''
        Extracts text from a file
        Uses the textract library on specific extensions
        '''

        matches = dict()

        suffix = Path(str(file)).suffix.lower()

        # textract
        if suffix in self.textract_extensions:
            binary_content = textract.process(str(file), encoding='utf-8')
            text_content = better_decode(binary_content)

        # normal
        elif self.match_magic(file):
            with open(str(file), 'rb') as f:
                binary_content = f.read()
            text_content = better_decode(binary_content)

        else:
            return matches

        # try to convert to UTF-8 for grep-friendliness
        try:
            binary_content = text_content.encode('utf-8')
        except Exception:
            pass
            
        # count the matches
        for _filter, match in self.match(text_content):
            try:
                matches[_filter] += 1
            except KeyError:
                matches[_filter] = 1

        for _filter, match_count in matches.items():
            log.info(ColoredFormatter.green(f'{pretty_filename}: matched "{_filter.pattern}" {match_count:,} times'))
            # run grep for pretty output
            if not self.quiet:
                self.grep(binary_content, _filter.pattern)

        return matches