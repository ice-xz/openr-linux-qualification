"""Deliberately killable supervisor for the one parent-death case."""
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parent/'vendor'))
from activation import RELEASE_ENABLED
from supervisor import Session, Limits, exclusive_json
from linux_backend import LinuxBackend,proc_identity

class ReportingBackend(LinuxBackend):
    def read(self,seconds):
        chunks=super().read(seconds)
        for stream,data in chunks:
            if stream=='stdout':
                self.buffer+=data
                if not self.ready:
                    for line in self.buffer.splitlines():
                        try: value=json.loads(line)
                        except (ValueError,UnicodeError): continue
                        if 'descendant' in value and value.get('uid')==65534:
                            identity=proc_identity(value['descendant'])
                            if set(identity['uids'])!={65534} or value['descendant'] not in map(int,self._read('cgroup.procs').split()):
                                raise RuntimeError('descendant not contained')
                            exclusive_json(self.ready_path,{'identity':self.identity,
                                'descendant_ready':value,'descendant_identity':identity,
                                'descendant_contained':True,'victim_pid':__import__('os').getpid()})
                            self.ready=True
        return chunks

def main(root,group):
    if not RELEASE_ENABLED: raise RuntimeError('review-only victim lock')
    root=Path(root); case=root/'evidence/parent-death'
    limits=Limits(seconds=25,memory=128*1024**2,pids=16,output=16384,interval=.1,cleanup_seconds=5)
    backend=ReportingBackend(group,[root],limits,65534,65534,case/'watchdog.json')
    backend.buffer=b''; backend.ready=False; backend.ready_path=case/'ready.json'
    session=Session(backend,case/'commands',limits)
    session.run([sys.executable,'-I',str(root/'code/payload.py'),'parent-death'],str(root/'work'),
                {'LANG':'C','PATH':'/usr/bin:/bin','TMPDIR':str(root/'work')})
    session.close()

if __name__=='__main__': main(*sys.argv[1:])
