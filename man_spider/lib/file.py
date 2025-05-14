import io
from .util import *
from .errors import *
from pathlib import Path


class RemoteFile():
    '''
    Represents a file on an SMB share
    Passed from a spiderling up to its parent spide
r    '''

    def __init__(self, name, share, target, size=0):

        self.share = share
        self.target = target
        self.name = name
        self.size = size
        self.smb_client = None

        file_suffix = Path(name).suffix.lower()
        self.tmp_filename = Path('/tmp/.manspider') / (random_string(15) + file_suffix)


    def get(self, smb_client=None):
        '''
        Downloads file to self.tmp_filename

        NOTE: SMBConnection() can't be passed through a multiprocessing queue
              This means that smb_client must be set after the file arrives at Spider()
        '''

        if smb_client is None and self.smb_client is None:
            raise FileRetrievalError('Please specify smb_client')

        with open(str(self.tmp_filename), 'wb') as f:
            try:
                smb_client.conn.getFile(self.share, self.name, f.write)
            except Exception as e:
                e = handle_impacket_error(e, smb_client, self.share, self.name)
                if 'Error occurs while reading from remote(104)' in str(e):
                    log.debug(f'Connection reset during file download, attempting to rebuild connection')
                    smb_client.rebuild(str(e))
                    # Retry the download once after rebuild
                    try:
                        smb_client.conn.getFile(self.share, self.name, f.write)
                    except Exception as e2:
                        e2 = handle_impacket_error(e2, smb_client, self.share, self.name)
                        raise FileRetrievalError(f'Error retrieving file "{str(self)}": {str(e2)[:150]}')
                else:
                    raise FileRetrievalError(f'Error retrieving file "{str(self)}": {str(e)[:150]}')


    def __str__(self):

        return f'{self.target}\\{self.share}\\{self.name}'
