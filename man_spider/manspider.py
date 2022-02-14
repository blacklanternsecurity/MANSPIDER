#!/usr/bin/env python3

import sys
import pathlib
import logging
import argparse
import traceback
from .lib import *
from time import sleep
import multiprocessing


# set up logging
log = logging.getLogger('manspider')
log.setLevel(logging.INFO)


def go(options):

    log.info('MANSPIDER command executed: ' + ' '.join(sys.argv))

    try:

        # warn if --or-logic is enabled
        if options.or_logic and options.content and not all([type(t) == pathlib.PosixPath for t in options.targets]):
            log.warning('WARNING: "--or-logic" causes files to be content-searched even if filename/extension filters do not match!!')
            sleep(2)

        # exit if no filters were specified
        if not (options.filenames or options.extensions or options.exclude_extensions or options.content):
            log.error('Please specify at least one of --filenames, --content, --extensions, or --exclude-extensions')
            return

        # exit if --maxdepth is invalid
        if options.maxdepth <= 0:
            log.error('--maxdepth must be greater than zero')
            return

        log.info(f'Skipping files larger than {bytes_to_human(options.max_filesize)}')
        log.info(f'Using {options.threads:,} threads')

        manspider = MANSPIDER(options)
        manspider.start()

    except KeyboardInterrupt:
        log.critical('Interrupted')

    except Exception as e:
        if log.level <= logging.DEBUG:
            log.critical(traceback.format_exc())
        else:
            log.critical(f'Critical error (-v to debug): {e}')

    finally:
        # make sure temp files are cleaned up before exiting
        #rmdir(manspider.tmp_dir)
        pass


def main():

    interrupted = False

    examples = '''

    # EXAMPLES

    Example 1: Search the network for filenames that may contain creds
    $ manspider 192.168.0.0/24 -f passw user admin account network login logon cred -d evilcorp -u bob -p Passw0rd

    Example 2: Search for XLSX files containing "password"
    $ manspider share.evilcorp.local -c password -e xlsx -d evilcorp -u bob -p Passw0rd

    Example 3: Search for interesting file extensions
    $ manspider share.evilcorp.local -e bat com vbs ps1 psd1 psm1 pem key rsa pub reg txt cfg conf config -d evilcorp -u bob -p Passw0rd

    Example 4: Search for finance-related files
    $ manspider share.evilcorp.local --dirnames bank financ payable payment reconcil remit voucher vendor eft swift -f '[0-9]{5,}' -d evilcorp -u bob -p Passw0rd
    '''

    parser = argparse.ArgumentParser(description='Scan for juicy data on SMB shares. Matching files and logs are stored in $HOME/.manspider. All filters are case-insensitive.')
    parser.add_argument('targets', nargs='+',   type=make_targets,          help='IPs, Hostnames, CIDR ranges, or files containing targets to spider (NOTE: local searching also supported, specify directory name or keyword "loot" to search downloaded files)')
    parser.add_argument('-u', '--username',     default='',                 help='username for authentication')
    parser.add_argument('-p', '--password',     default='',                 help='password for authentication')
    parser.add_argument('-d', '--domain',       default='',                 help='domain for authentication')
    parser.add_argument('-l','--loot-dir',      default='',                 help='loot directory (default ~/.manspider/)')
    parser.add_argument('-m', '--maxdepth',     type=int,   default=10,     help='maximum depth to spider (default: 10)')
    parser.add_argument('-H', '--hash',         default='',                 help='NTLM hash for authentication')
    parser.add_argument('-t', '--threads',      type=int,   default=5,      help='concurrent threads (default: 5)')
    parser.add_argument('-f', '--filenames', nargs='+', default=[],         help=f'filter filenames using regex (space-separated)', metavar='REGEX')
    parser.add_argument('-e', '--extensions',nargs='+', default=[],         help='only show filenames with these extensions (space-separated, e.g. `docx xlsx` for only word & excel docs)', metavar='EXT')
    parser.add_argument('--exclude-extensions',nargs='+', default=[],       help='ignore files with these extensions', metavar='EXT')
    parser.add_argument('-c', '--content',   nargs='+', default=[],         help='search for file content using regex (multiple supported)', metavar='REGEX')
    parser.add_argument('--sharenames',      nargs='+', default=[],         help='only search shares with these names (multiple supported)', metavar='SHARE')
    parser.add_argument('--exclude-sharenames', nargs='*', default=['IPC$', 'C$', 'ADMIN$', 'PRINT$'],help='don\'t search shares with these names (multiple supported)', metavar='SHARE')
    parser.add_argument('--dirnames',      nargs='+', default=[],           help='only search directories containing these strings (multiple supported)', metavar='DIR')
    parser.add_argument('--exclude-dirnames', nargs='+', default=[],        help='don\'t search directories containing these strings (multiple supported)', metavar='DIR')
    parser.add_argument('-q', '--quiet',   action='store_true',             help='don\'t display matching file content')
    parser.add_argument('-n', '--no-download',   action='store_true',       help='don\'t download matching files')
    parser.add_argument('-mfail', '--max-failed-logons', type=int,          help='limit failed logons', metavar='INT')
    parser.add_argument('-o', '--or-logic', action='store_true',            help=f'use OR logic instead of AND (files are downloaded if filename OR extension OR content match)')
    parser.add_argument('-s', '--max-filesize', type=human_to_int, default=human_to_int('10M'), help=f'don\'t retrieve files over this size, e.g. "500K" or ".5M" (default: 10M)', metavar='SIZE')
    parser.add_argument('-v', '--verbose', action='store_true',             help='show debugging messages')
    

    syntax_error = False
    try:

        if len(sys.argv) == 1:
            parser.print_help()
            sys.exit(1)

        options = parser.parse_args()

        if options.verbose:
            log.setLevel('DEBUG')

        # make sure extension formats are valid
        for i, extension in enumerate(options.extensions):
            if extension and not extension.startswith('.'):
                extension = f'.{extension}'
            options.extensions[i] = extension.lower()

        # make sure extension blacklist is valid
        for i, extension in enumerate(options.exclude_extensions):
            if not extension.startswith('.'):
                extension = f'.{extension}'
            options.exclude_extensions[i] = extension.lower()

        # lowercase share names
        options.sharenames = [s.lower() for s in options.sharenames]
        options.exclude_sharenames = [s.lower() for s in options.exclude_sharenames]

        # lowercase directory names
        options.dirnames = [s.lower() for s in options.dirnames]
        options.exclude_dirnames = [s.lower() for s in options.exclude_dirnames]

        # deduplicate targets
        targets = set()
        [[targets.add(t) for t in g] for g in options.targets]
        options.targets = list(targets)

        p = multiprocessing.Process(target=go, args=(options,), daemon=False)
        p.start()
        listener.start()

    except argparse.ArgumentError as e:
        syntax_error = True
        log.error(e)
        log.error('Check your syntax')
        sys.exit(2)

    except KeyboardInterrupt:
        log.critical('Interrupted')
        sys.exit(1)

    # pretty format all errors if we're not debugging
    except Exception as e:
        if log.level <= logging.DEBUG:
            log.critical(traceback.format_exc())
        else:
            log.critical(f'Critical error (-v to debug): {e}')

    finally:
        if '-h' in sys.argv or '--help' in sys.argv or len(sys.argv) == 1 or syntax_error:
            print(examples)
        sleep(1)
        try:
            # wait for go to finish
            p.join()
        except:
            pass
        try:
            # stop the log listener
            listener.stop()
        except:
            pass


if __name__ == '__main__':
    main()