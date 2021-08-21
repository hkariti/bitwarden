import subprocess
import os
import json

class BitWarden:
    def __init__(self, path='/usr/local/bin:/usr/bin', cmd='bw'):
        self._cmd = cmd
        self.sessionkey = None
        self._environ_base = dict(PATH=path, HOME=os.environ['HOME'])

    def _run_bw(self, *args, environ={}):
        return subprocess.run((self._cmd,) + args, shell=False, stdin=subprocess.DEVNULL, capture_output=True, env={ **self._environ_base, **environ }, text=True)

    def bw(self, *args, session=None, environ={}):
        if session:
            args = args + ('--session', session)
        ret = self._run_bw(*args, environ=environ)
        if ret.returncode != 0:
            raise BitWardenError(f"bw exited with return code {ret.returncode}.\nStdout:\n{ret.stdout}\nStderr:\n{ret.stderr}", runinfo=ret)

        return ret.stdout

    def unlock(self, password):
        if self.sessionkey is None:
            self.sessionkey = self.bw("unlock", "--passwordenv", "BW_PASS", "--raw", environ=dict(BW_PASS=password))
        return self
        
    def lock(self):
        self.bw("lock")
        self.sessionkey = None

    def get_item(self, item_id):
        try:
            item = self.bw("get", "item", item_id, session=self.sessionkey)
            return json.loads(item)
        except BitWardenError as e:
            if e.runinfo.stderr == 'Not found.':
                return None 
            raise

    def get_password(self, item_id):
        return self.get_item(item_id)['login']['password']

    def __enter__(self):
        return self

    def __exit__(self, *args, **kwargs):
        self.lock()

class BitWardenError(Exception):
    def __init__(self, message, runinfo):
        self.message = message
        self.runinfo = runinfo
