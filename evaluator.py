"""Acceptance is based on real receipts, not exit-code-only assertions."""
def assess(mode,receipt,kernel,watchdog=None):
    errors=[]
    clean=receipt.get('cleanup') or {}
    if clean.get('empty') is not True or clean.get('reaped') is not True: errors.append('cleanup incomplete')
    ident=receipt.get('identity') or {}
    if not isinstance(ident.get('start_ticks'),int) or set(ident.get('uids',[]))!={65534}:
        errors.append('payload identity missing/wrong')
    if receipt.get('returncode') is None: errors.append('exit code missing')
    reason=receipt.get('reason') or ''
    expected={'nonzero':'nonzero/missing exit','timeout':'deadline','descendant':'deadline',
              'output':'output limit','memory':None,'pids':None}
    if mode in ('success','containment'):
        if receipt.get('success') is not True or receipt.get('output_complete') is not True: errors.append('positive control failed')
    else:
        if receipt.get('success') is not False: errors.append('negative case was accepted')
        if expected.get(mode) and expected[mode] not in reason: errors.append('wrong failure mechanism')
    if mode=='nonzero' and receipt.get('returncode')!=7: errors.append('wrong deliberate exit')
    if mode=='memory' and not (kernel.get('memory.events',{}).get('max',0)>0): errors.append('no memory limit event')
    if mode=='pids' and not (kernel.get('pids.events',{}).get('max',0)>0): errors.append('no pids rejection event')
    if mode=='output' and receipt.get('output_complete') is not False: errors.append('overflow hidden')
    if kernel.get('cgroup.events',{}).get('populated')!=0: errors.append('group not empty')
    if watchdog is not None and (watchdog.get('success') is not True or watchdog.get('empty') is not True):
        errors.append('watchdog close failed')
    return {'pass':not errors,'errors':errors,'case':mode}

def assess_parent_death(victim_rc,ready,kernel,watchdog):
    errors=[]
    if victim_rc!=-9: errors.append('victim was not killed as specified')
    if not ready.get('identity') or not ready.get('descendant_ready'): errors.append('no contained descendant evidence')
    child=ready.get('descendant_identity') or {}
    if ready.get('descendant_contained') is not True or set(child.get('uids',[]))!={65534} or not isinstance(child.get('start_ticks'),int):
        errors.append('descendant kernel identity missing')
    if kernel.get('cgroup.events',{}).get('populated')!=0: errors.append('residual group')
    if watchdog.get('reason')!='parent pipe closed' or watchdog.get('kill_requested') is not True or watchdog.get('empty') is not True:
        errors.append('independent watchdog mechanism not demonstrated')
    return {'pass':not errors,'errors':errors,'case':'parent-death'}
