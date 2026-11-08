"""Closed release gate. No parameter or workflow input can flip this constant."""
import datetime
import json
import re
from pathlib import Path

RELEASE_ENABLED=False
HERE=Path(__file__).resolve().parent
STOP=datetime.datetime.fromisoformat('2026-11-08T01:09:35+00:00')

def context_errors(contract,ctx,now):
    errors=[]
    if contract.get('execution_authorized') is not True: errors.append('not authorized')
    repo=contract.get('repository')
    if not repo or not re.fullmatch(r'ice-xz/[A-Za-z0-9_.-]+',repo): errors.append('repository unbound')
    if ctx.get('repository')!=repo or ctx.get('visibility')!='public': errors.append('repository scope')
    if ctx.get('runner_environment')!='github-hosted' or ctx.get('runner_os')!='Linux': errors.append('hosted Linux required')
    if ctx.get('event')!='workflow_dispatch': errors.append('manual dispatch only')
    if str(ctx.get('run_number'))!='1' or str(ctx.get('run_attempt'))!='1': errors.append('not first attempt of first run')
    if not re.fullmatch(r'[0-9]+',str(ctx.get('run_id',''))): errors.append('run identity')
    if ctx.get('ref')!='refs/heads/'+contract['branch']: errors.append('branch')
    expected=f"{repo}/{contract['workflow_path']}@refs/heads/{contract['branch']}"
    if ctx.get('workflow_ref')!=expected: errors.append('workflow identity')
    sha=ctx.get('sha','')
    if not re.fullmatch(r'[0-9a-f]{40}',sha) or ctx.get('approved_sha')!=sha: errors.append('reviewed commit')
    if now>=STOP or (STOP-now).total_seconds()<600: errors.append('calendar cannot contain whole job')
    return errors

def require_release(ctx):
    contract=json.loads((HERE/'contract.json').read_text(encoding='utf-8'))
    errors=context_errors(contract,ctx,datetime.datetime.now(datetime.timezone.utc))
    if not RELEASE_ENABLED or contract['release_enabled'] is not True:
        errors.insert(0,'local review lock: no CI/service/payload execution')
    if errors: raise RuntimeError('; '.join(errors))
    return contract
