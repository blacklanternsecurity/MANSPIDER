import ntpath
import struct
import logging
import os
from .errors import *
from impacket.nmb import NetBIOSError, NetBIOSTimeout
from impacket.smbconnection import SessionError, SMBConnection
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.types import Principal
import traceback

# set up logging
log = logging.getLogger('manspider.smb')


class SMBClient:
    '''
    Wrapper around impacket's SMBConnection() object
    '''

    def __init__(self, server, username, password, domain, nthash, use_kerberos=False, dc_ip='', no_pass=False):
        self.server = server
        self.conn = None
        self.username = username
        self.password = password
        self.domain = domain
        self.nthash = nthash
        self.use_kerberos = use_kerberos
        self.dc_ip = dc_ip
        self.no_pass = no_pass
        self.tgt = None
        self.tgs = None
        
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

                if self.use_kerberos:
                    try:
                        log.info(f'Starting Kerberos authentication for {self.domain}\\{self.username}')
                        log.info('Getting new TGT with password authentication')
                        try:
                            # Create Principal object for Kerberos authentication
                            if '@' not in self.username:
                                username = f'{self.username}@{self.domain}'
                            else:
                                username = self.username
                            
                            # Create Principal object with correct parameters for Impacket 0.12.0
                            principal = Principal(username, type=1)
                            
                            # Get TGT using Principal object with explicit encryption types
                            self.tgt = getKerberosTGT(
                                principal,
                                self.password,
                                self.domain,
                                kdcHost=self.dc_ip,
                                lmhash=None,
                                nthash=None,
                                aesKey=None,
                                etype=(23, 17, 18)  # RC4, AES128, AES256
                            )
                            
                            # Login with Kerberos using the TGT
                            self.conn.kerberosLogin(
                                self.username,
                                self.password,
                                self.domain,
                                self.tgt,
                                kdcHost=self.dc_ip,
                                useCache=False
                            )
                            log.info(f'Successfully authenticated to {self.server} using Kerberos')
                            return True
                        except Exception as e:
                            log.error(f'Kerberos authentication failed: {str(e)}')
                            if log.level <= logging.DEBUG:
                                log.error(f'Full error details: {traceback.format_exc()}')
                            return False
                    except Exception as e:
                        log.error(f'Kerberos authentication failed: {str(e)}')
                        if log.level <= logging.DEBUG:
                            log.error(f'Full error details: {traceback.format_exc()}')
                        return False
                else:
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
            if 'Error occurs while reading from remote(104)' in str(e):
                log.debug(f'Connection reset during list operation, attempting to rebuild connection')
                self.rebuild(str(e))
                # Retry the operation once after rebuild
                try:
                    for f in self.conn.listPath(share, nt_path):
                        if f.get_longname() not in ['', '.', '..']:
                            yield f
                except Exception as e2:
                    e2 = handle_impacket_error(e2, self)
                    raise FileListError(f'{e2.args}: Error listing files at "{share}{nt_path}"')
            else:
                raise FileListError(f'{e.args}: Error listing files at "{share}{nt_path}"')



    def rebuild(self, error=''):
        '''
        Rebuild our SMBConnection() if it gets borked
        '''

        log.debug(f'Rebuilding connection to {self.server} after error: {error}')
        if self.use_kerberos:
            try:
                log.debug('Creating new SMB connection for Kerberos rebuild')
                self.conn = SMBConnection(self.server, self.server, sess_port=445, timeout=20)
                
                # Always get fresh tickets for rebuild
                if self.no_pass:
                    log.debug('Using ccache file for Kerberos rebuild')
                    if 'KRB5CCNAME' not in os.environ:
                        log.error('KRB5CCNAME environment variable not set')
                        return
                    
                    ccache = CCache.loadFile(os.environ['KRB5CCNAME'])
                    principal = Principal(self.username, type=1, realm=self.domain)
                    self.tgt = ccache.getCredential(principal)
                    if self.tgt is None:
                        log.error(f'No valid credentials found in ccache for {self.username}@{self.domain}')
                        return
                    log.debug('Successfully loaded TGT from ccache for rebuild')
                else:
                    log.debug('Getting new TGT for Kerberos rebuild')
                    try:
                        self.tgt = getKerberosTGT(self.username, self.password, self.domain, kdcHost=self.dc_ip, lmhash=None, nthash=None)
                        log.debug('Successfully obtained new TGT for rebuild')
                    except Exception as e:
                        log.error(f'Failed to get TGT: {str(e)}')
                        if log.level <= logging.DEBUG:
                            log.error(f'Full error details: {traceback.format_exc()}')
                        return
                
                # Get new TGS for SMB
                log.debug(f'Getting new TGS for {self.server}@{self.domain} for rebuild')
                try:
                    self.tgs = getKerberosTGS(self.tgt, self.server, self.domain, kdcHost=self.dc_ip)
                    log.debug('Successfully obtained new TGS for rebuild')
                except Exception as e:
                    log.error(f'Failed to get TGS: {str(e)}')
                    if log.level <= logging.DEBUG:
                        log.error(f'Full error details: {traceback.format_exc()}')
                    return
                
                # Login with Kerberos
                log.debug('Attempting Kerberos login for rebuild')
                try:
                    self.conn.kerberosLogin(self.username, '', self.domain, tgs=self.tgs)
                    log.debug('Kerberos rebuild successful')
                except Exception as e:
                    log.error(f'Failed to login with Kerberos: {str(e)}')
                    if log.level <= logging.DEBUG:
                        log.error(f'Full error details: {traceback.format_exc()}')
                    return
                return
            except Exception as e:
                log.error(f'Failed to rebuild Kerberos connection: {e}')
                if log.level <= logging.DEBUG:
                    log.error(f'Full error details: {traceback.format_exc()}')
                return
        else:
            self.login(refresh=True)