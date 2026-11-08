"""Linux containment handshake. Called only by the reviewed backend, never CI directly."""
import ctypes
import os
import resource
import signal
import sys

def main(args):
    if sys.platform != 'linux': raise RuntimeError('Linux required')
    group,ready,release,uid,gid = map(int,args[:5])
    argv = args[5:]
    if uid <= 0 or gid <= 0 or not argv or not os.path.isabs(argv[0]):
        raise RuntimeError('invalid identity/command')
    libc = ctypes.CDLL(None,use_errno=True)
    parent=os.getppid()
    if parent==1 or libc.prctl(1,signal.SIGKILL,0,0,0)!=0:  # PR_SET_PDEATHSIG
        raise RuntimeError('cannot bind parent death')
    if os.getppid()!=parent: raise RuntimeError('parent exited during binding')
    os.write(group,str(os.getpid()).encode())
    os.close(group)
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    # setuid clears PDEATHSIG on Linux; restore after identity transition.
    if libc.prctl(1,signal.SIGKILL,0,0,0)!=0 or os.getppid()!=parent:
        raise RuntimeError('parent death binding changed')
    if libc.prctl(38,1,0,0,0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise OSError(ctypes.get_errno(),'no_new_privs')
    os.write(ready,b'R'); os.close(ready)
    if os.read(release,1) != b'G': raise RuntimeError('release not granted')
    os.close(release)
    os.execve(argv[0],argv,dict(os.environ))

if __name__ == '__main__':
    main(sys.argv[1:])
