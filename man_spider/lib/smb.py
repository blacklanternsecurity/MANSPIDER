import ntpath
import logging
from .errors import *
from contextlib import suppress
from impacket.nmb import NetBIOSError, NetBIOSTimeout
from impacket.smbconnection import SessionError, SMBConnection

# set up logging
log = logging.getLogger('manspider.smb')


class SMBClient:
    '''
    Wrapper around impacket's SMBConnection() object
    '''

    def __init__(self, server, username, password, domain, nthash, use_kerberos=False, aes_key="", dc_ip=None):

        self.server = server

        self.conn = None

        self.username = username
        self.password = password
        self.domain = domain
        self.nthash = nthash
        self.use_kerberos = use_kerberos
        self.aes_key = aes_key
        self.dc_ip = dc_ip
        self.hostname = None
        self.dns_domain = None
        if self.nthash:
            self.lmhash = 'aad3b435b51404eeaad3b435b51404ee'
        else:
            self.lmhash = ''
        self._shares = None


    def list_shares(self):
        '''
        List shares on the SMB server
        '''
        resp = self.conn.listShares()
        for i in range(len(resp)):
            sharename = resp[i]['shi1_netname'][:-1]
            log.debug(f'{self.server}: Found share: {sharename}')
            yield sharename


    @property
    def shares(self):
        if self._shares is None:
            try:
                self._shares = list(self.list_shares())
            except Exception as e:
                e = self.handle_impacket_error(e)
                log.debug(f'{self.server}: Error listing shares: {e}, retrying...')
                self.rebuild(e)
                try:
                    self._shares = list(self.list_shares())
                except Exception as e:
                    e = self.handle_impacket_error(e)
                    log.warning(f'{self.server}: Error listing shares: {e}')
                    self.rebuild(e)
        return self._shares or []


    def get_hostname(self):
        '''
        Get the hostname from the SMB connection
        '''
        try:
            conn = SMBConnection(
                self.server,
                self.server,
                None,
                445,
                timeout=10,
            )
            with suppress(Exception):
                conn.login("", "")

            if self.hostname is None:
                try:
                    # Get the server name from SMB
                    self.hostname = str(conn.getServerName()).strip().replace("\x00", "").lower()
                    if self.hostname:
                        log.debug(f'{self.server}: Got hostname: {self.hostname}')
                    else:
                        log.debug(f'{self.server}: No hostname found')
                except Exception as e:
                    log.debug(f'{self.server}: Error getting hostname from SMB: {e}')
                    self.hostname = ""

            if self.dns_domain is None:
                try:
                    self.dns_domain = str(conn.getServerDNSDomainName()).strip().replace("\x00", "").lower()
                    if self.dns_domain:
                        log.debug(f'{self.server}: Got DNS domain: {self.dns_domain}')
                    else:
                        log.debug(f'{self.server}: No DNS domain found')
                except Exception as e:
                    log.debug(f'{self.server}: Error getting DNS domain: {e}')
                    self.dns_domain = (self.domain if self.domain else "")

        except Exception as e:
            log.debug(f'{self.server}: Error getting hostname: {e}')

        return self.hostname, self.domain

    def login(self, refresh=False, first_try=True):
        '''
        Create a new SMBConnection object (if there isn't one already or if refresh is True)
        Attempt to log in, and switch to null session if logon fails
        Return True if logon succeeded
        Return False if logon failed
        '''

        target_server = self.server
        if self.use_kerberos:
            hostname, domain = self.get_hostname()
            if hostname:
                target_server = hostname
                if domain:
                    target_server = f"{hostname}.{domain}"

        if self.conn is None or refresh:
            try:
                self.conn = SMBConnection(target_server, target_server, sess_port=445, timeout=20)
            except Exception as e:
                log.debug(impacket_error(e))
                return None

            try:

                if self.username in [None, '', 'Guest'] and first_try:
                    # skip to guest / null session
                    assert False

                user_str = self.username
                if self.domain:
                    user_str = f'{self.domain}\\{self.username}'
                log.debug(f'{target_server} ({self.server}): Authenticating as "{user_str}"')

                if self.use_kerberos:
                    self.conn.kerberosLogin(
                        self.username,
                        self.password,
                        self.domain,
                        self.lmhash,
                        self.nthash,
                        self.aes_key,
                        kdcHost=self.dc_ip,
                    )
                # pass the hash if requested
                elif self.nthash and not self.password:
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
                    e = self.handle_impacket_error(e, display=True)

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
            e = self.handle_impacket_error(e)
            raise FileListError(f'{e.args}: Error listing files at "{share}{nt_path}"')


    def rebuild(self, error=''):
        '''
        Rebuild our SMBConnection() if it gets borked
        '''
        log.debug(f'Rebuilding connection to {self.server} after error: {error}')
        self.login(refresh=True)


    def handle_impacket_error(self, e, share='', filename='', display=False):
        '''
        Handle arbitrary Impacket errors
        this is needed because the library doesn't implement proper inheritance for its exceptions
        '''
        resource_str = '/'.join([self.server, share, filename]).rstrip('/')

        if type(e) == KeyboardInterrupt:
            raise
        elif type(e) in (NetBIOSError, NetBIOSTimeout, BrokenPipeError, SessionError, CSessionError):
            # the connection may need to be rebuilt
            if type(e) in (SessionError, CSessionError):
                if any([x in str(e) for x in ('PASSWORD_EXPIRED',)]):
                    self.rebuild(e)
            else:
                self.rebuild(e)
        if type(e) in native_impacket_errors:
            e = impacket_error(e)
        if display:
            log.debug(f'{resource_str}: {str(e)[:150]}')

        return e
