"""Independent deadline/parent-pipe watchdog, Linux-only main, offline-testable core.
Only inherited FDs address the task's cgroup. No names/PIDs are searched to kill.
"""
import json
import os
import selectors
import sys
import time

def supervise(deadline, control, kill, empty, clock=time.monotonic, sleep=time.sleep):
    reason=None
    while reason is None:
        try:
            if clock()>=deadline:
                reason='global deadline'
                break
            command=control(min(.2,max(0,deadline-clock())))
            if command==b'C':
                if empty(): return {'success':True,'empty':True,'reason':'normal close','kill_requested':False}
                reason='normal close with residual processes'
            elif command==b'': reason='parent pipe closed'
            elif command not in (None,): reason='invalid control message'
        except BaseException as exc:
            reason='watchdog observation/control failure: '+type(exc).__name__
    result={'success':False,'empty':False,'reason':reason,'kill_requested':True}
    try:
        kill()
        end=clock()+10
        while clock()<end:
            if empty(): result['empty']=True; break
            sleep(.05)
    except BaseException as exc: result['error']=type(exc).__name__+': '+str(exc)
    return result

def main(args):
    if sys.platform!='linux': raise RuntimeError('Linux required')
    control_fd,kill_fd,events_fd,receipt_fd,ready_fd=map(int,args[:5])
    deadline=float(args[5])
    with selectors.DefaultSelector() as selector:
        selector.register(control_fd,selectors.EVENT_READ)
        def control(timeout):
            return os.read(control_fd,1) if selector.select(timeout) else None
        def kill(): os.write(kill_fd,b'1')
        def empty():
            os.lseek(events_fd,0,os.SEEK_SET)
            fields=dict(line.split() for line in os.read(events_fd,4096).decode().splitlines())
            return fields['populated']=='0'
        os.write(ready_fd,b'R'); os.close(ready_fd)
        result=supervise(deadline,control,kill,empty)
        raw=json.dumps(result).encode()
        os.write(receipt_fd,raw[:4096]); os.fsync(receipt_fd)
        return 0 if result['empty'] else 2

if __name__=='__main__': raise SystemExit(main(sys.argv[1:]))
