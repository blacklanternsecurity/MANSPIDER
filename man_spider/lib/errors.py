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
