"""Closed-by-default ephemeral hosted-VM bootstrap. No download/install commands."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import time
sys.path.insert(0,str(Path(__file__).resolve().parent))
from activation import require_release,HERE

CAP=8*1024**2

def service_argv(root,run_id):
    return ['/usr/bin/systemd-run','--unit=openr-qual-'+run_id,'--slice=system.slice','--wait','--pipe','--collect',
        '--property=Type=exec','--property=Delegate=yes','--property=MemoryMax=1G',
        '--property=MemorySwapMax=0','--property=TasksMax=64','--property=CPUQuota=200%',
        '--property=CPUQuotaPeriodSec=100ms','--property=RuntimeMaxSec=480',
        '--property=TimeoutStopSec=10','--property=KillMode=control-group',
        '--property=SendSIGKILL=yes','--property=Nice=19','--property=IOAccounting=yes',
        '--property=IOSchedulingClass=idle','--property=LimitCORE=0','--property=LimitFSIZE=8388608',
        '/usr/bin/python3','-I',str(root/'code/qualification.py'),str(root),str(root/'context.json')]

def pack_evidence(directory,output):
    members=[]; total=0
    for p in sorted(directory.rglob('*')):
        if p.is_dir(): continue
        s=p.lstat()
        if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1: raise RuntimeError('unsafe evidence member')
        total+=s.st_size
        if total>CAP or len(members)>=256: raise RuntimeError('evidence cap')
        members.append(p)
    if not members: raise RuntimeError('no evidence')
    # Publish only after all size checks. Failed partials are never upload targets.
    with output.with_name(output.name+'.publish-once').open('xb'):
        pass  # Exclusive writer claim; retained on every failure, never retried.
    if output.exists(): raise FileExistsError(output)
    partial=output.with_name(output.name+'.partial')
    with partial.open('xb') as f:
        with tarfile.open(fileobj=f,mode='w:gz') as tar:
            for p in members: tar.add(p,arcname=p.relative_to(directory).as_posix(),recursive=False)
    if partial.stat().st_size>CAP: raise RuntimeError('compressed evidence exceeds cap')
    # Same-directory rename by the sole claimed writer, in the private task path.
    partial.rename(output)
    return {'bytes':output.stat().st_size,'sha256':hashlib.sha256(output.read_bytes()).hexdigest(),
            'members':len(members)}

def verify_sources():
    manifest=json.loads((HERE/'public-manifest.json').read_text())
    for rel,digest in manifest.items():
        p=HERE/rel
        if p.resolve()!=p or not p.is_file() or p.stat().st_nlink!=1: raise RuntimeError('source redirection')
        if hashlib.sha256(p.read_bytes()).hexdigest()!=digest: raise RuntimeError('source hash changed')
    return manifest

def require_unused_unit(unit,env):
    probe=subprocess.run(['/usr/bin/systemctl','show',unit,'--property=LoadState','--value'],
                         env=env,capture_output=True,timeout=5)
    if probe.returncode!=0 or probe.stdout.strip()!=b'not-found':
        raise RuntimeError('unit unavailable or ownership unknown; no launch or stop')
    return {'returncode':probe.returncode,'stdout':probe.stdout.decode(errors='replace'),
            'stderr':probe.stderr.decode(errors='replace')}

def privileged(ctx,base):
    require_release(ctx)  # before any privileged mutation
    if sys.platform!='linux' or os.geteuid()!=0: raise RuntimeError('Linux root bootstrap required')
    import pwd
    if pwd.getpwuid(65534).pw_name!='nobody': raise RuntimeError('unexpected payload account')
    base=Path(base)
    if base.resolve(strict=True)!=base or str(base)!='/home/runner/work/_temp':
        raise RuntimeError('unexpected hosted runner temp root; no path fallback')
    if 'VERSION_ID="24.04"' not in Path('/etc/os-release').read_text(): raise RuntimeError('wrong runner OS')
    if min(shutil.disk_usage(base).free,shutil.disk_usage(HERE).free)<10*1024**3:
        raise RuntimeError('disk reserve')
    manifest=verify_sources()
    unit='openr-qual-'+ctx['run_id']+'.service'
    clean_env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'}
    unused=require_unused_unit(unit,clean_env)
    root=base/('openr-qual-'+ctx['run_id'])
    root.mkdir(mode=0o755)  # exclusive, no reuse/adoption
    root.chmod(0o755)
    os.umask(0o077)
    code=root/'code'; code.mkdir(mode=0o755)
    (code/'vendor').mkdir(mode=0o755)
    code.chmod(0o755); (code/'vendor').chmod(0o755)
    evidence=root/'evidence'; evidence.mkdir()
    work=root/'work'; work.mkdir(); os.chown(work,65534,65534)
    for rel in manifest:
        if rel.endswith('.py') or rel=='contract.json':
            destination=code/rel
            shutil.copyfile(HERE/rel,destination); destination.chmod(0o644)
    (root/'context.json').write_text(json.dumps(ctx))
    result={'service_exit':None,'cleanup':None,'qualified':False}
    (evidence/'unit-before.json').write_text(json.dumps(unused))
    start=time.monotonic()
    try:
        for tool in ('/usr/bin/systemd-run','/usr/bin/systemctl','/usr/bin/python3'):
            if not Path(tool).is_file(): raise RuntimeError('missing preinstalled tool: '+tool)
        with (evidence/'service.stdout').open('xb') as out,(evidence/'service.stderr').open('xb') as err:
            run=subprocess.run(service_argv(root,ctx['run_id']),env=clean_env,
                               stdout=out,stderr=err,stdin=subprocess.DEVNULL,timeout=510)
            result['service_exit']=run.returncode
    except BaseException as exc:
        result['error']=type(exc).__name__+': '+str(exc)
    finally:
        # Exact unit only. No killall, broad pkill, Docker configuration or host network calls.
        empty=False
        try:
            stop=subprocess.run(['/usr/bin/systemctl','stop',unit],env=clean_env,
                                capture_output=True,timeout=20)
            show=subprocess.run(['/usr/bin/systemctl','show',unit,'--property=LoadState,ActiveState,SubState,ControlGroup'],
                                env=clean_env,capture_output=True,timeout=5)
            cg=Path('/sys/fs/cgroup/system.slice')/unit
            empty=not cg.exists()
            if cg.exists():
                from_dict=dict(x.split() for x in (cg/'cgroup.events').read_text().splitlines())
                empty=from_dict.get('populated')=='0'
            result['cleanup']={'stop_rc':stop.returncode,'show_rc':show.returncode,
                'show_stdout':show.stdout.decode(errors='replace'),'show_stderr':show.stderr.decode(errors='replace'),
                'exact_service_cgroup_empty_or_removed':empty}
        except BaseException as exc:
            result['cleanup']={'exact_service_cgroup_empty_or_removed':False,'error':str(exc)}
        report=evidence/'qualification-result.json'
        result['qualified']=bool(result['service_exit']==0 and empty and report.exists()
                                  and json.loads(report.read_text()).get('pass') is True)
        result['elapsed_seconds']=time.monotonic()-start
        (evidence/'bootstrap-result.json').write_text(json.dumps(result,indent=2))
        for p in evidence.rglob('*'):
            if p.is_file(): p.chmod(0o644)
            elif p.is_dir(): p.chmod(0o755)
        evidence.chmod(0o755)
    return result,evidence

def main():
    # Default invocation prints a refusal before subprocess or privilege operations.
    ctx=json.loads(os.environ.get('QUAL_CONTEXT','{}')) if len(sys.argv)==1 else json.loads(Path(sys.argv[2]).read_text())
    require_release(ctx)
    if len(sys.argv)>1:
        if sys.argv[1]!='--root': raise RuntimeError('unexpected mode')
        result,evidence=privileged(ctx,sys.argv[3])
        info=pack_evidence(evidence,HERE/'qualification-evidence.tar.gz')
        print(json.dumps({'qualified':result['qualified'],'evidence':info}))
        return 0 if result['qualified'] else 1
    verify_sources()
    ctx['image_version']=os.environ.get('ImageVersion')
    if not ctx['image_version']: raise RuntimeError('runner image version missing')
    ticket=HERE/'qualification-request.json'
    with ticket.open('x') as f: json.dump(ctx,f)
    # One call, no retry, no inherited GitHub token passed through sudo.
    command=['/usr/bin/sudo','-n','/usr/bin/python3','-I',str(HERE/'bootstrap.py'),'--root',str(ticket),os.environ['RUNNER_TEMP']]
    return subprocess.run(command,env={'PATH':'/usr/bin:/bin','LANG':'C'},timeout=570).returncode

if __name__=='__main__':
    try: raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({'qualified':False,'reason':str(exc)}))
        raise SystemExit(78)
