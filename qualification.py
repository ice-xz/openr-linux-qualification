"""Runs only within the exact temporary qualification service; no installs."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parent/'vendor'))
from activation import require_release
from supervisor import Session, Limits, Stop, exclusive_json
from linux_backend import LinuxBackend, pairs
from evaluator import assess, assess_parent_death

def persist_parent_death(case,rc,ready,actual,watchdog):
    # Persist evaluation inputs first, including the direct-child wait outcome.
    # A pass label alone cannot substitute for replayable exit evidence.
    receipt={'returncode':rc,'pid':ready.get('victim_pid'),
             'ready':ready,'kernel':actual,'watchdog':watchdog,
             'observation':'Popen.kill followed by Popen.wait on owned direct child'}
    exclusive_json(case/'exit-evidence.json',receipt)
    saved=json.loads((case/'exit-evidence.json').read_text())
    return assess_parent_death(saved['returncode'],saved['ready'],saved['kernel'],saved['watchdog'])

def kernel(group):
    return {name:pairs((group/name).read_text()) for name in
            ('memory.events','pids.events','cgroup.events')}

def service_group(run_id):
    lines=Path('/proc/self/cgroup').read_text().splitlines()
    paths=[x[3:] for x in lines if x.startswith('0::')]
    if len(paths)!=1: raise Stop('unified cgroup missing')
    p=Path('/sys/fs/cgroup'+paths[0])
    if p.name!='openr-qual-'+run_id+'.service': raise Stop('not the exact dedicated service')
    if p.resolve()!=p: raise Stop('cgroup path redirection')
    return p

def outer_ok(group,root):
    import shutil
    expected={'memory.max':'1073741824','memory.swap.max':'0','pids.max':'64',
              'cpu.max':'200000 100000'}
    for name,value in expected.items():
        if (group/name).read_text().strip()!=value: raise Stop('outer limit mismatch: '+name)
    if int((group/'memory.current').read_text())>=1073741824 or int((group/'pids.current').read_text())>=64:
        raise Stop('outer resource line')
    # Hierarchical child-limit events are expected in declared negative cases;
    # local events detect pressure on the OUTER service itself.
    m=pairs((group/'memory.events.local').read_text())
    p=pairs((group/'pids.events.local').read_text())
    if m['max'] or m['oom'] or m['oom_kill'] or p['max']: raise Stop('outer kernel event')
    if shutil.disk_usage(root).free<10*1024**3: raise Stop('disk reserve')

class WatchedBackend(LinuxBackend):
    def __init__(self,*args,outer,root,**kwargs):
        self.outer,self.root=outer,root
        super().__init__(*args,**kwargs)
    def snapshot(self):
        outer_ok(self.outer,self.root)
        return super().snapshot()

def case_limits(mode):
    return Limits(seconds=20,memory=64*1024**2 if mode=='memory' else 128*1024**2,
                  pids=8 if mode=='pids' else 16,output=1024 if mode=='output' else 16384,
                  interval=.1,cleanup_seconds=5)

def ordinary(mode,parent,root,deadline):
    group=parent/('openr-review-'+mode)
    group.mkdir()  # existing name aborts; never adopt another group
    case=root/'evidence'/mode; case.mkdir()
    limit=case_limits(mode)
    backend=WatchedBackend(group,[root],limit,65534,65534,case/'watchdog.json',outer=parent,root=root)
    exclusive_json(case/'limits-readback.json',{n:(group/n).read_text().strip() for n in
        ('memory.max','memory.swap.max','memory.oom.group','pids.max','cpu.max')})
    session=Session(backend,case/'commands',limit)
    session.deadline=min(session.deadline,deadline)
    # backend's watchdog original deadline is <=20s, also bounded by outer service.
    try:
        try:
            session.run([sys.executable,'-I',str(root/'code/payload.py'),mode],str(root/'work'),
                        {'PATH':'/usr/bin:/bin','LANG':'C','TMPDIR':str(root/'work')},
                        timeout_seconds=2 if mode in ('timeout','descendant') else 8)
        except Stop:
            pass  # Evaluator must prove the exact intended mechanism below.
        closed=session.close()
        record=json.loads((case/'commands/001.receipt.json').read_text())
        actual=kernel(group)
        result=assess(mode,record,actual,closed)
        if mode in ('success','containment'):
            marker=b'QUALIFICATION_OK' if mode=='success' else b'CONTAINMENT_OK'
            if marker not in (case/'commands/001.stdout.bin').read_bytes():
                result['pass']=False; result['errors'].append('missing positive marker')
        exclusive_json(case/'kernel-after.json',actual)
        exclusive_json(case/'evaluation.json',result)
        if not result['pass']: raise Stop('case failed: '+mode+': '+str(result['errors']))
        return result
    finally:
        # Do not erase any logs. Group cleanup uses exact path created above.
        (group/'cgroup.kill').write_text('1')
        if pairs((group/'cgroup.events').read_text())['populated']==0: group.rmdir()

def parent_death(parent,root,deadline):
    case=root/'evidence/parent-death'; case.mkdir()
    group=parent/'openr-review-parent-death'; group.mkdir()
    proc=None
    try:
        with (case/'victim.stdout').open('xb') as out,(case/'victim.stderr').open('xb') as err:
            proc=subprocess.Popen([sys.executable,'-I',str(root/'code/victim.py'),str(root),str(group)],
                stdout=out,stderr=err,stdin=subprocess.DEVNULL,env={'LANG':'C','PATH':'/usr/bin:/bin'},
                start_new_session=True)
            end=min(deadline,time.monotonic()+10)
            ready=None
            while time.monotonic()<end:
                outer_ok(parent,root)
                path=case/'ready.json'
                if path.exists():
                    try: ready=json.loads(path.read_text())
                    except json.JSONDecodeError: pass
                    if ready: break
                if proc.poll() is not None: raise Stop('victim exited before ready')
                time.sleep(.1)
            if not ready: raise Stop('no real descendant ready evidence')
            # Popen owns this unreaped direct child; no name/UID-wide signalling.
            proc.kill(); rc=proc.wait(timeout=5)
            end=min(deadline,time.monotonic()+12)
            wd=None
            while time.monotonic()<end:
                outer_ok(parent,root)
                p=case/'watchdog.json'
                if p.exists() and p.stat().st_size:
                    try: wd=json.loads(p.read_text())
                    except json.JSONDecodeError: pass
                    if wd: break
                time.sleep(.1)
            actual=kernel(group)
            result=persist_parent_death(case,rc,ready,actual,wd or {})
            exclusive_json(case/'kernel-after.json',actual)
            exclusive_json(case/'evaluation.json',result)
            if not result['pass']: raise Stop('watchdog parent-death evidence failed')
            return result
    finally:
        if proc is not None and proc.poll() is None:
            proc.kill(); proc.wait(timeout=5)
        (group/'cgroup.kill').write_text('1')
        if pairs((group/'cgroup.events').read_text())['populated']==0: group.rmdir()

def run(root,ctx):
    contract=require_release(ctx)
    root=Path(root).resolve(strict=True)
    parent=service_group(ctx['run_id'])
    result={'pass':False,'cases':[],'reason':None,'openr_executed':False}
    deadline=time.monotonic()+contract['test_deadline_seconds']
    try:
        outer_ok(parent,root)
        manager=parent/'manager'; manager.mkdir()
        (manager/'cgroup.procs').write_text(str(os.getpid()))
        if (parent/'cgroup.procs').read_text().strip(): raise Stop('delegated parent still populated')
        (parent/'cgroup.subtree_control').write_text('+cpu +memory +pids')
        exclusive_json(root/'evidence/environment.json',{
            'uname':list(os.uname()),'python':sys.version,'service_cgroup':str(parent),
            'runner_image':ctx.get('image_version'),'wrapper_sha':ctx['sha'],'run_id':ctx['run_id'],
            'limits':{n:(parent/n).read_text().strip() for n in ('memory.max','pids.max','cpu.max')},
            'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()})
        for mode in contract['cases']:
            if time.monotonic()>=deadline: raise Stop('global qualification deadline')
            outer_ok(parent,root)
            result['cases'].append(parent_death(parent,root,deadline) if mode=='parent-death'
                                   else ordinary(mode,parent,root,deadline))
        outer_ok(parent,root)
        result['pass']=True
    except BaseException as exc:
        result['reason']=type(exc).__name__+': '+str(exc)
    finally:
        exclusive_json(root/'evidence/qualification-result.json',result)
    return 0 if result['pass'] else 1

if __name__=='__main__':
    raise SystemExit(run(sys.argv[1],json.loads(Path(sys.argv[2]).read_text())))
