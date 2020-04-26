# MAN-SPIDER
### Crawl SMB shares for juicy information.  File content searching + regex is supported!

![manspider](https://user-images.githubusercontent.com/20261699/74963251-6a08de80-53df-11ea-88f4-60c39665dfa2.gif)

### File types supported:
- `DOCX`
- `XLSX`
- `PDF`
- `PPTX`
- any text-based format
- and many more!!

### MAN-SPIDER will crawl every share on every target system.  If provided creds don't work, it will fall back to "guest", then to a null session.
![manspider](https://user-images.githubusercontent.com/20261699/80316979-f9ab7e80-87ce-11ea-9628-3c22a07e8378.png)

## Installation:
Optional: `apt install` these dependencies for legacy `.doc` support
- `antiword`
~~~
$ git clone https://github.com/blacklanternsecurity/MANSPIDER
$ cd MANSPIDER
$ pipenv --python 3 shell
(manspider) $ pip install -r requirements.txt
~~~

## Example #1: Search the network for juicy-sounding filenames
NOTE: matching files are automatically downloaded into `./loot`!
~~~
./manspider.py 192.168.0.0/24 -v -f passw user admin network login logon -d evilcorp -u bob -p Spring2020
~~~

## Example #2: Search for XLSX files containing "password"
NOTE: matching files are automatically downloaded into `./loot`!
~~~
./manspider.py share.evilcorp.local -v -c password -e xlsx -d evilcorp -u bob -p Spring2020
~~~

## Usage Note:
Reasonable defaults prevent unwanted scenarios like spidering a single target forever.  All of these can be overridden:
- **default spider depth: 10** (override with `-m`)
- **default max filesize: 10** (override with `-s`)
- **default threads: 20** (override with `-t`)
- **shares excluded: `C$`, `IPC$`, `ADMIN$`** (override with `--exclude-sharenames`)

## Usage:
~~~
usage: manspider.py [-h] [-u USERNAME] [-p PASSWORD] [-d DOMAIN] [-m MAXDEPTH]
                    [-H HASH] [-t THREADS] [-f REGEX [REGEX ...]]
                    [-e EXT [EXT ...]] [--exclude-extensions EXT [EXT ...]]
                    [-c REGEX [REGEX ...]] [--sharenames SHARE [SHARE ...]]
                    [--exclude-sharenames SHARE [SHARE ...]]
                    [--dirnames DIR [DIR ...]]
                    [--exclude-dirnames DIR [DIR ...]] [-q] [-n] [-mfail INT]
                    [-o] [-s SIZE] [-v]
                    targets [targets ...]

Scan for juicy info sitting on SMB shares. Matching files go into /loot. Logs
go into /logs. All filters are case-insensitive.

positional arguments:
  targets               IPs, Hostnames, or CIDR ranges to spider (files also
                        supported, NOTE: specify "loot" to only search local
                        files in ./loot)

optional arguments:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        username for authentication
  -p PASSWORD, --password PASSWORD
                        password for authentication
  -d DOMAIN, --domain DOMAIN
                        domain for authentication
  -m MAXDEPTH, --maxdepth MAXDEPTH
                        maximum depth to spider (default: 10)
  -H HASH, --hash HASH  NTLM hash for authentication
  -t THREADS, --threads THREADS
                        concurrent threads (default: 20)
  -f REGEX [REGEX ...], --filenames REGEX [REGEX ...]
                        filter filenames using regex (space-separated)
  -e EXT [EXT ...], --extensions EXT [EXT ...]
                        only show filenames with these extensions (space-
                        separated, e.g. `docx xlsx` for only word & excel
                        docs)
  --exclude-extensions EXT [EXT ...]
                        ignore files with these extensions
  -c REGEX [REGEX ...], --content REGEX [REGEX ...]
                        search for file content using regex (multiple
                        supported)
  --sharenames SHARE [SHARE ...]
                        only search shares with these names (multiple
                        supported)
  --exclude-sharenames SHARE [SHARE ...]
                        don't search shares with these names (multiple
                        supported)
  --dirnames DIR [DIR ...]
                        only search directories containing these strings
                        (multiple supported)
  --exclude-dirnames DIR [DIR ...]
                        don't search directories containing these strings
                        (multiple supported)
  -q, --quiet           don't display matching file content
  -n, --no-download     don't download matching files into /loot
  -mfail INT, --max-failed-logons INT
                        limit failed logons
  -o, --or-logic        use OR logic instead of AND (files are downloaded if
                        filename OR extension OR content match)
  -s SIZE, --max-filesize SIZE
                        don't retrieve files over this size, e.g. "500K" or
                        ".5M" (default: 10M)
  -v, --verbose         show debugging messages
~~~