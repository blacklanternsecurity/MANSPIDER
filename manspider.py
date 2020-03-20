#!/usr/bin/env python3

import sys
import logging
import argparse
from lib import *


# set up logging
log = logging.getLogger('manspider')
log.setLevel('INFO')


if __name__ == '__main__':

    interrupted = False

    parser = argparse.ArgumentParser(description='Scan for juicy info sitting on SMB shares. Matching files go into /loot.')
    parser.add_argument('targets', nargs='+',   type=str_to_hosts,          help='IPs, Hostnames, or CIDR ranges to spider (files also supported)')
    parser.add_argument('-u', '--username',     default='',                 help='username for authentication')
    parser.add_argument('-p', '--password',     default='',                 help='password for authentication')
    parser.add_argument('-d', '--domain',       default='',                 help='domain for authentication (e.g. evilcorp.local)')
    parser.add_argument('-m', '--maxdepth',     type=int,   default=10,     help='maximum depth to spider (default: 10)')
    parser.add_argument('-H', '--hash',         default='',                 help='NTLM hash for authentication')
    parser.add_argument('-t', '--threads',      type=int,   default=25,     help='concurrent threads (default: 100)')
    parser.add_argument('-f', '--filenames', nargs='+', default=[],         help='filter filenames using regex (space-separated)')
    parser.add_argument('-e', '--extensions',nargs='+', default=[],         help='only show filenames with these extensions (space-separated)')
    parser.add_argument('-c', '--content',   nargs='+', default=[],         help='search for file content using regex (space-separated)')
    parser.add_argument('--sharenames',      nargs='+', default=[],         help='only search shares with these names (space-separated)')
    parser.add_argument('--exclude-sharenames', nargs='+', default=[],      help='don\'t search shares with these names (space-separated)')
    parser.add_argument('-q', '--quiet',   action='store_true',             help='don\'t display matching file content')
    parser.add_argument('-n', '--no-download',   action='store_true',       help='don\'t download matching files into /loot')
    parser.add_argument('-mfail', '--max-failed-logons', type=int,          help='limit failed logons')
    parser.add_argument('-s', '--max-filesize', type=human_to_int, default=human_to_int('10M'), help=f'don\'t retrieve files over this size in bytes (default: 10M)')
    parser.add_argument('-v', '--verbose', action='store_true',             help='show debugging messages')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    try:

        options = parser.parse_args()

        log.info(f'Skipping files larger than {bytes_to_human(options.max_filesize)}')

        if options.verbose:
            log.setLevel('DEBUG')

        log.info(f'Using {options.threads:,} threads')

        # make sure extension formats are valid
        for i, extension in enumerate(options.extensions):
            if not extension.startswith('.'):
                extension = f'.{extension}'
            options.extensions[i] = extension.lower()

        # lowercase share names
        options.sharenames = [s.lower() for s in options.sharenames]
        options.exclude_sharenames = [s.lower() for s in options.exclude_sharenames]

        assert options.maxdepth > 0, 'maxdepth must be greater than zero'

        targets = set()
        [[targets.add(t) for t in g] for g in options.targets]
        options.targets = targets

        manspider = MANSPIDER(options)
        manspider.start()

    except argparse.ArgumentError as e:
        log.error(e)
        log.error('Check your syntax')
        sys.exit(2)

    except KeyboardInterrupt:
        log.critical('Interrupted')
        sys.exit(1)

    # pretty format all errors if we're not debugging
    except Exception as e:
        if log.level <= logging.DEBUG:
            raise
        else:
            log.critical(f'Critical error (-v to debug): {e}')

    finally:
        # stop the log listener
        listener.stop()