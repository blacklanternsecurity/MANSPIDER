import struct
import logging
from impacket.nmb import NetBIOSError, NetBIOSTimeout
from impacket.smb import SessionError, UnsupportedFeature
from impacket.smbconnection import SessionError as CSessionError

# set up logging
log = logging.getLogger('manspider')


class MANSPIDERError(Exception):
    pass

class FileRetrievalError(MANSPIDERError):
    pass

class ShareListError(MANSPIDERError):
    pass

class FileListError(MANSPIDERError):
    pass

class LogonFailure(MANSPIDERError):
    pass


native_impacket_errors = (
    struct.error,
    NetBIOSError,
    NetBIOSTimeout,
    SessionError,
    CSessionError,
    UnsupportedFeature,
)


impacket_errors = (
    OSError,
    BrokenPipeError,
) + native_impacket_errors


def impacket_error(e):
    '''
    Tries to format impacket exceptions nicely
    '''

    if type(e) in (SessionError, CSessionError):
        try:
            error_str = e.getErrorString()[0]
            e.args = (error_str,)
        except (IndexError,):
            pass
    if not e.args:
        e.args = ('',)
    return e


def handle_impacket_error(e, smb_client, share='', filename='', display=False):
    '''
    Handle arbitrary Impacket errors
    this is needed because the library doesn't implement proper inheritance for its exceptions
    '''

    resource_str = '/'.join([smb_client.server, share, filename]).rstrip('/')

    if type(e) == KeyboardInterrupt:
        raise
    elif type(e) in (NetBIOSError, NetBIOSTimeout, BrokenPipeError, SessionError, CSessionError):
        # the connection may need to be rebuilt
        if type(e) in (SessionError, CSessionError):
            if any([x in str(e) for x in ('PASSWORD_EXPIRED',)]):
                smb_client.rebuild(e)
        else:
            smb_client.rebuild(e)
    if type(e) in native_impacket_errors:
        e = impacket_error(e)
    if display:
        log.debug(f'{resource_str}: {str(e)[:150]}')

    return e