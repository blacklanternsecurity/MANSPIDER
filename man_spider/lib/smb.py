import ntpath
import struct
import logging
from .errors import *
from impacket.nmb import NetBIOSError, NetBIOSTimeout
from impacket.smbconnection import SessionError, SMBConnection

# set up logging
log = logging.getLogger('manspider.smb')


class SMBClient:
    '''
    Wrapper around impacket's SMBConnection() object
    '''

    def __init__(self, server, username, password, domain, nthash):

        self.server = server

        self.conn = None

        self.username = username
        self.password = password
        self.domain = domain
        self.nthash = nthash
        if self.nthash:
            self.lmhash = 'aad3b435b51404eeaad3b435b51404ee'
        else:
            self.lmhash = ''


    @property
    def shares(self):

        try:
            resp = self.conn.listShares()
            for i in range(len(resp)):
                sharename = resp[i]['shi1_netname'][:-1]
                log.debug(f'{self.server}: Found share: {sharename}')
                yield sharename
            
        except Exception as e:
            e = handle_impacket_error(e, self)
            log.warning(f'{self.server}: Error listing shares: {e}')
            


    def login(self, refresh=False, first_try=True):
        '''
        Create a new SMBConnection object (if there isn't one already or if refresh is True)
        Attempt to log in, and switch to null session if logon fails
        Return True if logon succeeded
        Return False if logon failed
        '''

        if self.conn is None or refresh:
            try:
                self.conn = SMBConnection(self.server, self.server, sess_port=445, timeout=20)
            except Exception as e:
                log.debug(impacket_error(e))
                return None

            try:

                if self.username in [None, '', 'Guest'] and first_try:
                    # skip to guest / null session
                    assert False

                log.debug(f'{self.server}: Authenticating as "{self.domain}\\{self.username}"')

                # pass the hash if requested
                if self.nthash and not self.password:
                    self.conn.login(
                        self.username,
                        '',
                        lmhash=self.lmhash,
                        nthash=self.nthash,
                        domain=self.domain,
                    )
                # otherwise, normal login
                else:
                    self.conn.login(
                        self.username,
                        self.password,
                        domain=self.domain,
                    )

                log.info(f'{self.server}: Successful login as "{self.username}"')
                return True

            except Exception as e:

                if type(e) != AssertionError:
                    e = handle_impacket_error(e, self, display=True)

                # try guest account, then null session if logon failed
                if first_try:

                    bad_statuses = ['LOGON_FAIL', 'PASSWORD_EXPIRED', 'LOCKED_OUT', 'SESSION_DELETED']
                    if any([s in str(e) for s in bad_statuses]):
                        for s in bad_statuses:
                            if s in str(e):
                                log.warning(f'{self.server}: {s}: {self.username}')

                    log.debug(f'{self.server}: Trying guest session')
                    self.username = 'Guest'
                    self.password = ''
                    self.domain = ''
                    self.nthash = ''
                    guest_success = self.login(refresh=True, first_try=False)
                    if not guest_success:
                        log.debug(f'{self.server}: Switching to null session')
                        self.username = ''
                        self.login(refresh=True, first_try=False)

            return False

        else:
            return True


    def ls(self, share, path):
        '''
        List files in share/path
        Raise FileListError if there's a problem
        @byt3bl33d3r it's really not that bad
        '''

        nt_path = ntpath.normpath(f'{path}\\*')

        # for every file/dir in "path"
        try:
            for f in self.conn.listPath(share, nt_path):
                # exclude current and parent directory
                if f.get_longname() not in ['', '.', '..']:
                    yield f
        except Exception as e:
            e = handle_impacket_error(e, self)
            raise FileListError(f'{e.args}: Error listing files at "{share}{nt_path}"')



    def rebuild(self, error=''):
        '''
        Rebuild our SMBConnection() if it gets borked
        '''

        log.debug(f'Rebuilding connection to {self.server} after error: {error}')
        self.login(refresh=True)