# MAN-SPIDER
Crawl SMB shares for juicy information.  File content searching + regex is supported!

![manspider](https://user-images.githubusercontent.com/20261699/74963251-6a08de80-53df-11ea-88f4-60c39665dfa2.gif)

## Installation:
~~~
$ cd MANSPIDER
$ pipenv --python 3 shell
(manspider) $ pip install -r requirements.txt
~~~

## Example #1: Search the network for filenames containing juicy strings
NOTE: matching files are automatically downloaded into `./loot`!
~~~
./manspider.py -v -f passw user admin network login logon -d evilcorp -u bob -p Spring2020 192.168.0.0/24
~~~

## Example #2: Search for XLSX files containing "password" in the content
NOTE: matching files are automatically downloaded into `./loot`!
~~~
./manspider.py -v -c password -e xlsx -d evilcorp -u bob -p Spring2020 share.evilcorp.local
~~~

## Usage:
~~~
$ ./manspider.py --help
usage: manspider.py [-h] [-u USERNAME] [-p PASSWORD] [-d DOMAIN] [-m MAXDEPTH]
                    [-H HASH] [-t THREADS] [-f FILENAMES [FILENAMES ...]]
                    [-e EXTENSIONS [EXTENSIONS ...]]
                    [-c CONTENT [CONTENT ...]]
                    [--sharenames SHARENAMES [SHARENAMES ...]]
                    [--exclude-sharenames EXCLUDE_SHARENAMES [EXCLUDE_SHARENAMES ...]]
                    [-q] [-n] [-mfail MAX_FAILED_LOGONS] [-s MAX_FILESIZE]
                    [-v]
                    targets [targets ...]

Scan for juicy info sitting on SMB shares. Matching files go into /loot.

positional arguments:
  targets               IPs, Hostnames, or CIDR ranges to spider (files also
                        supported)

optional arguments:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        username for authentication
  -p PASSWORD, --password PASSWORD
                        password for authentication
  -d DOMAIN, --domain DOMAIN
                        domain for authentication (e.g. evilcorp.local)
  -m MAXDEPTH, --maxdepth MAXDEPTH
                        maximum depth to spider (default: 10)
  -H HASH, --hash HASH  NTLM hash for authentication
  -t THREADS, --threads THREADS
                        concurrent threads (default: 100)
  -f FILENAMES [FILENAMES ...], --filenames FILENAMES [FILENAMES ...]
                        filter filenames using regex (space-separated)
  -e EXTENSIONS [EXTENSIONS ...], --extensions EXTENSIONS [EXTENSIONS ...]
                        only show filenames with these extensions (space-
                        separated)
  -c CONTENT [CONTENT ...], --content CONTENT [CONTENT ...]
                        search for file content using regex (space-separated)
  --sharenames SHARENAMES [SHARENAMES ...]
                        only search shares with these names (space-separated)
  --exclude-sharenames EXCLUDE_SHARENAMES [EXCLUDE_SHARENAMES ...]
                        don't search shares with these names (space-separated)
  -q, --quiet           don't display matching file content
  -n, --no-download     don't download matching files into /loot
  -mfail MAX_FAILED_LOGONS, --max-failed-logons MAX_FAILED_LOGONS
                        limit failed logons
  -s MAX_FILESIZE, --max-filesize MAX_FILESIZE
                        don't retrieve files over this size in bytes (default:
                        10M)
  -v, --verbose         show debugging messages
~~~