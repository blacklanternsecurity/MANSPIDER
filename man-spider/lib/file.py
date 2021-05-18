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
        self.tmp_filename = Path('/tmp/manspider') / (random_string(15) + file_suffix)


    def get(self, smb_client=None):
        '''
        Downloads file to self.tmp_filename

        NOTE: SMBConnection() can't be passed through a multiprocessing queue
              This means that smb_client must be set after the file arrives at Spider()
        '''

        if smb_client is None and self.smb_client is None:
            raise FileRetrievalError('Please specify smb_client')

        #memfile = io.BytesIO()
        with open(str(self.tmp_filename), 'wb') as f:

            try:
                smb_client.conn.getFile(self.share, self.name, f.write)
            except Exception as e:
                handle_impacket_error(e, smb_client, self.share, self.name)
                raise FileRetrievalError(f'Error retrieving file "{str(self)}": {str(e)[:150]}')

        # reset cursor back to zero so .read() will return the whole file
        #memfile.seek(0)


    def __str__(self):

        return f'{self.target}\\{self.share}\\{self.name}'
