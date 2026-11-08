"""Unexecuted Linux cgroup-v2 backend for review; no automatic setup/privilege.

Precondition: dedicated ephemeral VM, trusted supervisor outside payload group,
unprivileged build UID unable to move itself to other groups. This backend is NOT
permission to create a VM or change a shared host. No callable CLI build entry.
"""
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import sys
import time
from supervisor import Stop

def pairs(text):
    result = {}
    for line in text.splitlines():
        k,v = line.split()
        if k in result: raise Stop("duplicate kernel key")
        result[k] = int(v)
    return result

def proc_identity(pid):
    p = Path('/proc')/str(pid)
    stat = (p/'stat').read_text()
    # comm may contain spaces and parentheses. Fields after last ')' start at 3.
    fields = stat[stat.rfind(')')+2:].split()
    uid = next(x.split()[1:] for x in (p/'status').read_text().splitlines() if x.startswith('Uid:'))
    return {"pid":pid,"start_ticks":int(fields[19]),"uids":list(map(int,uid))}

class LinuxBackend:
    def __init__(self, group, disk_paths, limits, build_uid, build_gid, watchdog_receipt):
        if sys.platform != 'linux': raise Stop('Linux required')
        if os.geteuid() != 0 or build_uid <= 0 or build_gid <= 0:
            raise Stop('requires privileged supervisor and distinct non-root payload identity')
        self.group = Path(group)
        if not self.group.is_absolute() or self.group.resolve(strict=True) != self.group:
            raise Stop('group path redirection')
        parent = Path('/sys/fs/cgroup')
        if self.group == parent or not self.group.is_relative_to(parent):
            raise Stop('not dedicated cgroup path')
        mounts = Path('/proc/self/mountinfo').read_text().splitlines()
        if not any(' - cgroup2 ' in x and x.split()[4] == str(parent) for x in mounts):
            raise Stop('unverified cgroup2 mount')
        if not self.group.name.startswith('openr-review-'):
            raise Stop('unexpected task group name')
        self.uid,self.gid = build_uid,build_gid
        self.disk_paths = [Path(x).resolve(strict=True) for x in disk_paths]
        if not self.disk_paths or parent.stat().st_dev != self.group.stat().st_dev:
            raise Stop('missing disk paths/invalid cgroup filesystem')
        self.devino = (self.group.stat().st_dev,self.group.stat().st_ino)
        self.proc = None
        self.selector = None
        self.eof = False
        self.limits = limits
        self.global_deadline=None
        self.watchdog=None
        self.watchdog_control=None
        self.watchdog_receipt=Path(watchdog_receipt)
        if self._pairs('cgroup.events').get('populated') != 0:
            raise Stop('group not empty')
        if self._read('cgroup.type').strip() != 'domain': raise Stop('non-domain cgroup')
        # Delegation must be supplied separately; never change ancestor controls.
        self.settings = {'memory.max':str(limits.memory),'memory.swap.max':'0',
                         'memory.oom.group':'1','pids.max':str(limits.pids),
                         'cpu.max':'200000 100000'}
        for name,val in self.settings.items():
            self._write(name,val)
            if self._read(name).strip() != val: raise Stop('limit readback mismatch')
        for name in ('cgroup.kill','cgroup.procs','memory.events','pids.events'):
            self._guard(name)

    def _guard(self, name):
        s = self.group.stat()
        if (s.st_dev,s.st_ino) != self.devino: raise Stop('group identity changed')
        p = self.group/name
        if p.is_symlink() or p.resolve(strict=True).parent != self.group:
            raise Stop('control file redirected')
        return p

    def _read(self,name): return self._guard(name).read_text()
    def _write(self,name,value): self._guard(name).write_text(value)
    def _pairs(self,name): return pairs(self._read(name))

    def snapshot(self):
        if self.watchdog is not None and self.watchdog.poll() is not None:
            raise Stop('watchdog exited before batch completion')
        for name,val in self.settings.items():
            if self._read(name).strip() != val: raise Stop('hard limit drift')
        mem,pid = self._pairs('memory.events'),self._pairs('pids.events')
        return {'memory':int(self._read('memory.current')),
                'pids':int(self._read('pids.current')),
                'disk_free':min(shutil.disk_usage(p).free for p in self.disk_paths),
                'memory_max_events':mem['max'],'oom_kill':mem['oom_kill'],
                'pids_max_events':pid['max']}

    def start(self, argv, cwd, env, deadline):
        if self.proc is not None: raise Stop('previous process not finalized')
        if self._pairs('cgroup.events')['populated'] != 0: raise Stop('nonempty before spawn')
        exe = Path(argv[0])
        if not exe.is_absolute() or not exe.is_file(): raise Stop('executable unavailable')
        # No secrets or LD/Python injection inherited. PATH is explicit.
        allowed = {'PATH','LANG','LC_ALL','HOME','TMPDIR','TMP','TEMP','MAKEFLAGS','CMAKE_BUILD_PARALLEL_LEVEL'}
        if set(env)-allowed: raise Stop('unreviewed environment variable')
        if self.global_deadline is None: raise Stop('global supervision deadline not bound')
        if self.watchdog is None: self._start_watchdog()
        self.selector = selectors.DefaultSelector()
        ready_r,ready_w = os.pipe()
        release_r,release_w = os.pipe()
        group_fd = os.open(self._guard('cgroup.procs'),os.O_WRONLY|os.O_NOFOLLOW)
        self.eof = False
        try:
            command = [sys.executable,'-I',str(Path(__file__).with_name('payload_gate.py')),
                       str(group_fd),str(ready_w),str(release_r),str(self.uid),str(self.gid),
                       *argv]
            self.proc = subprocess.Popen(command,cwd=cwd,env=env,stdin=subprocess.DEVNULL,
                       stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,
                       close_fds=True,pass_fds=(group_fd,ready_w,release_r))
            identity = proc_identity(self.proc.pid)
            os.close(ready_w); ready_w = -1
            os.close(release_r); release_r = -1
            with selectors.DefaultSelector() as ready:
                ready.register(ready_r,selectors.EVENT_READ)
                if not ready.select(max(0,min(5,deadline-time.monotonic()))):
                    raise Stop('containment handshake timeout')
                if os.read(ready_r,1) != b'R': raise Stop('containment handshake failed')
            if self.proc.pid not in map(int,self._read('cgroup.procs').split()):
                raise Stop('child not contained')
            # Gate drops identity/capability acquisition before releasing exec.
            now = proc_identity(self.proc.pid)
            if now['start_ticks'] != identity['start_ticks'] or set(now['uids']) != {self.uid}:
                raise Stop('payload identity not isolated')
            for name,pipe in [('stdout',self.proc.stdout),('stderr',self.proc.stderr)]:
                os.set_blocking(pipe.fileno(),False)
                self.selector.register(pipe,selectors.EVENT_READ,name)
            os.write(release_w,b'G')
            self.identity = now
            return {**now,'cgroup':str(self.group),'cgroup_dev_inode':self.devino}
        finally:
            for fd in (ready_r,ready_w,release_r,release_w,group_fd):
                if fd >= 0: os.close(fd)

    def read(self, seconds):
        chunks = []
        for key,_ in self.selector.select(max(0,min(1,seconds))):
            try: data = os.read(key.fileobj.fileno(),4096)
            except BlockingIOError: continue
            if data: chunks.append((key.data,data))
            else: self.selector.unregister(key.fileobj)
        self.eof = not self.selector.get_map()
        return chunks

    def poll(self): return None if self.proc is None else self.proc.poll()

    def finish(self, seconds):
        deadline = time.monotonic()+min(seconds,10)
        result = {'empty':False,'reaped':False,'returncode':None,'residual_before_cleanup':False}
        try:
            populated = self._pairs('cgroup.events')['populated']
            result['residual_before_cleanup'] = bool(populated and self.proc and self.proc.poll() is not None)
            # cgroup tree, not user-wide process names or arbitrary PIDs.
            self._write('cgroup.kill','1')
            # If gate failed before joining, Popen retains this unreaped child PID.
            if self.proc and self.proc.poll() is None:
                self.proc.kill()
            while time.monotonic() < deadline:
                empty = self._pairs('cgroup.events')['populated'] == 0
                rc = None if self.proc is None else self.proc.poll()
                if empty and (self.proc is None or rc is not None):
                    result.update(empty=True,reaped=True,returncode=rc)
                    break
                time.sleep(.05)
        finally:
            if self.selector: self.selector.close()
            if self.proc:
                for pipe in (self.proc.stdout,self.proc.stderr):
                    if pipe: pipe.close()
            # Do not delete cgroups/evidence, including on failure.
            if result['empty'] and result['reaped']: self.proc = None
        return result

    def set_deadline(self, deadline):
        if self.global_deadline is not None: raise Stop('cannot reset global deadline')
        self.global_deadline=deadline

    def _start_watchdog(self):
        control_r,control_w=os.pipe(); ready_r,ready_w=os.pipe()
        kill_fd=os.open(self._guard('cgroup.kill'),os.O_WRONLY|os.O_NOFOLLOW)
        events_fd=os.open(self._guard('cgroup.events'),os.O_RDONLY|os.O_NOFOLLOW)
        with self.watchdog_receipt.open('xb') as receipt:
            try:
                command=[sys.executable,'-I',str(Path(__file__).with_name('watchdog.py')),
                         str(control_r),str(kill_fd),str(events_fd),str(receipt.fileno()),str(ready_w),
                         str(self.global_deadline)]
                self.watchdog=subprocess.Popen(command,stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env={'LANG':'C'},
                    start_new_session=True,close_fds=True,
                    pass_fds=(control_r,kill_fd,events_fd,receipt.fileno(),ready_w))
                self.watchdog_control=control_w; control_w=-1
                os.close(ready_w); ready_w=-1
                with selectors.DefaultSelector() as ready:
                    ready.register(ready_r,selectors.EVENT_READ)
                    if not ready.select(max(0,min(5,self.global_deadline-time.monotonic()))) or os.read(ready_r,1)!=b'R':
                        raise Stop('watchdog handshake failed')
            finally:
                for fd in (control_r,control_w,ready_r,ready_w,kill_fd,events_fd):
                    if fd>=0: os.close(fd)

    def close(self):
        if self.watchdog is None: return {'success':True,'empty':True,'watchdog':'not started'}
        if self.watchdog_control is not None:
            try: os.write(self.watchdog_control,b'C')
            except BrokenPipeError: pass
            finally: os.close(self.watchdog_control); self.watchdog_control=None
        self.watchdog.wait(timeout=10)
        raw=self.watchdog_receipt.read_bytes()
        if not raw or len(raw)>4096: raise Stop('missing/oversize watchdog receipt')
        result=json.loads(raw)
        if self.watchdog.returncode!=0 or result.get('success') is not True or result.get('empty') is not True:
            raise Stop('watchdog did not close normally: '+str(result))
        return result
