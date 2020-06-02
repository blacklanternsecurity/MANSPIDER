# MAN-SPIDER
### Crawl SMB shares for juicy information.  File content searching + regex is supported!

![manspider](https://user-images.githubusercontent.com/20261699/74963251-6a08de80-53df-11ea-88f4-60c39665dfa2.gif)

### File types supported:
- `PDF`
- `DOCX`
- `XLSX`
- `PPTX`
- any text-based format
- and many more!!

### MAN-SPIDER will crawl every share on every target system.  If provided creds don't work, it will fall back to "guest", then to a null session.
![manspider](https://user-images.githubusercontent.com/20261699/80316979-f9ab7e80-87ce-11ea-9628-3c22a07e8378.png)

### Installation:
(Optional) `apt install` these dependencies to add additional file parsing capability:
- `antiword` (for legacy `.doc` support)
~~~
$ git clone https://github.com/blacklanternsecurity/MANSPIDER
$ cd MANSPIDER
$ pipenv --python 3 shell
(manspider) $ pip install -r requirements.txt
~~~

### Example #1: Search the network for juicy-sounding filenames
NOTE: matching files are automatically downloaded into `./loot`!
~~~
./manspider.py 192.168.0.0/24 -v -f passw user admin account network login logon cred -d evilcorp -u bob -p Passw0rd
~~~

### Example #2: Search for XLSX files containing "password"
NOTE: matching files are automatically downloaded into `./loot`!
~~~
./manspider.py share.evilcorp.local -v -c password -e xlsx -d evilcorp -u bob -p Passw0rd
~~~

### Example #3: Search for interesting file extensions
NOTE: matching files are automatically downloaded into `./loot`!
~~~
./manspider.py share.evilcorp.local -v -e bat com vbs ps1 psd1 psm1 reg txt cfg conf config -d evilcorp -u bob -p Passw0rd
~~~

### Usage Tip:
Reasonable defaults help prevent unwanted scenarios like getting stuck on a single target.  All of these can be overridden:
- **default spider depth: 10** (override with `-m`)
- **default max filesize: 10MB** (override with `-s`)
- **default threads: 5** (override with `-t`)
- **shares excluded: `C$`, `IPC$`, `ADMIN$`, `PRINT$`** (override with `--exclude-sharenames`)

### Usage Tip:
MAN-SPIDER accepts any combination of the following as targets:
- IPs
- hostnames
- subnets (CIDR format)
- files containing any of the above
- local folders containing files

For example, you could specify any or all of these:
- **`192.168.1.250`**
- **`share.evilcorp.local`**
- **`192.168.1.0/24`**
- **`smb_hosts.txt`**
- **`./loot`** (to search already-downloaded files)
    - NOTE: when searching local files, you must specify a directory, not an individual file

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
  targets               IPs, Hostnames, CIDR ranges, or files containing
                        targets to spider (NOTE: local searching also
                        supported, specify "./loot" to search downloaded
                        files)

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
                        concurrent threads (default: 5)
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