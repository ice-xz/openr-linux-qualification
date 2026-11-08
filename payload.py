"""Small Linux qualification stimuli, NEVER executed by local tests."""
import json
import os
from pathlib import Path
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parent))
from activation import RELEASE_ENABLED

def main(mode):
    if not RELEASE_ENABLED: raise RuntimeError('review-only payload lock')
    os.nice(19)
    print(json.dumps({'mode':mode,'pid':os.getpid(),'uid':os.getuid()}),flush=True)
    if mode=='success': print('QUALIFICATION_OK',flush=True); return 0
    if mode=='containment':
        path=next(x[3:] for x in Path('/proc/self/cgroup').read_text().splitlines() if x.startswith('0::'))
        group=Path('/sys/fs/cgroup'+path)
        targets=[group.parent/'cgroup.procs',group.parent/'manager/cgroup.procs',Path(__file__)]
        denied=0
        for target in targets:
            # Opening for write alone probes access; no actual value is written.
            try:
                fd=os.open(target,os.O_WRONLY); os.close(fd)
            except PermissionError: denied+=1
        status=Path('/proc/self/status').read_text()
        nnp=next(x.split()[1] for x in status.splitlines() if x.startswith('NoNewPrivs:'))
        if denied!=len(targets) or nnp!='1': return 9
        print('CONTAINMENT_OK',flush=True); return 0
    if mode=='nonzero': return 7
    if mode=='timeout': time.sleep(30); return 0
    if mode in ('descendant','parent-death'):
        pid=os.fork()
        if pid==0:
            os.setsid()
            print(json.dumps({'descendant':os.getpid(),'uid':os.getuid()}),flush=True)
            time.sleep(30); os._exit(0)
        if mode=='descendant': return 0
        time.sleep(30); return 0
    if mode=='output': os.write(1,b'X'*8192); return 0
    if mode=='memory':
        blocks=[]
        for _ in range(192): blocks.append(bytearray(1024*1024))
        return 9  # no OOM/limit event => failed test
    if mode=='pids':
        for _ in range(12):
            try: pid=os.fork()
            except OSError as exc:
                print(json.dumps({'fork_errno':exc.errno}),flush=True); time.sleep(15); return 8
            if pid==0: time.sleep(20); os._exit(0)
        return 9
    raise ValueError('unknown frozen case')

if __name__=='__main__': raise SystemExit(main(sys.argv[1]))
