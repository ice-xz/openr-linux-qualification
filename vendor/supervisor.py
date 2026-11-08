"""Bounded execution core. Linux backend is NOT qualified by offline tests.

Only an already-created, dedicated cgroup is accepted. This module never enables
controllers on a shared parent, installs packages, uses SSH, or dispatches CI.
Disk space is sampled, not a hard filesystem quota. This is not a security sandbox.
"""
from __future__ import annotations
import dataclasses
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import time

GIB = 1024**3
MIB = 1024**2

class Stop(RuntimeError):
    pass

@dataclasses.dataclass(frozen=True)
class Limits:
    seconds: float = 6600
    memory: int = 12 * GIB
    pids: int = 512
    disk_floor: int = 10 * GIB
    output: int = 32 * MIB
    interval: float = 1
    cleanup_seconds: float = 10

    def __post_init__(self):
        for key, cap in {"seconds":6600, "memory":12*GIB, "pids":512,
                         "output":32*MIB, "interval":1, "cleanup_seconds":10}.items():
            x = getattr(self, key)
            if type(x) not in (int, float) or not math.isfinite(x) or not 0 < x <= cap:
                raise Stop("invalid limit: " + key)
        for key in ("memory", "pids", "output", "disk_floor"):
            if type(getattr(self, key)) is not int:
                raise Stop("integer limit required: " + key)
        if self.disk_floor < 10*GIB:
            raise Stop("disk reserve decreased")

def check_snapshot(s, limits):
    for key in ("memory", "pids", "disk_free", "memory_max_events", "oom_kill", "pids_max_events"):
        if type(s.get(key)) is not int or s[key] < 0:
            raise Stop("missing/invalid observation: " + key)
    if s["memory"] >= limits.memory or s["pids"] >= limits.pids:
        raise Stop("memory/process stop line")
    if s["disk_free"] < limits.disk_floor:
        raise Stop("disk stop line")
    if any(s[k] for k in ("memory_max_events", "oom_kill", "pids_max_events")):
        raise Stop("kernel limit event")

def exclusive_json(path, value):
    with Path(path).open("x", encoding="utf-8") as f:
        json.dump(value, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())

def claim_once(root, run_id):
    if not re.fullmatch(r"[a-z0-9-]{1,64}", run_id):
        raise Stop("invalid run identity")
    root = Path(root).resolve(strict=True)
    exclusive_json(root/"consumed.json", {"run_id":run_id, "intent":"single batch; no retry"})

class Session:
    """One global deadline/output allowance across every command and stage.

    backend.start must return only after the child is contained; backend.finish
    must kill any residual descendants and confirm the group is empty. Any
    missing cleanup evidence stops the session permanently.
    """
    def __init__(self, backend, evidence, limits=Limits(), clock=time.monotonic,
                 wall_clock=lambda: datetime.datetime.now(datetime.timezone.utc)):
        self.backend, self.evidence, self.limits, self.clock = backend, Path(evidence), limits, clock
        calendar=datetime.datetime.fromisoformat('2026-11-08T01:09:35+00:00')
        self.wall_clock,self.calendar=wall_clock,calendar
        remaining=(calendar-wall_clock()).total_seconds()
        if remaining<=0: raise Stop('original calendar budget expired')
        self.deadline = clock() + min(limits.seconds,remaining)
        self.total_output = 0
        self.counter = 0
        self.stopped = False
        self.evidence.mkdir(exist_ok=False)
        if hasattr(backend,'set_deadline'): backend.set_deadline(self.deadline)

    def run(self, argv, cwd, env, timeout_seconds=None, max_output_bytes=None):
        if self.stopped:
            raise Stop("session terminal; retry prohibited")
        self.counter += 1
        prefix = self.evidence / ("%03d" % self.counter)
        receipt = {"argv":list(argv), "returncode":None, "cleanup":None,
                   "success":False, "reason":None, "output_complete":False}
        outputs = {"stdout":bytearray(), "stderr":bytearray()}
        command_deadline = self.deadline
        command_cap = self.limits.output-self.total_output
        started = False
        reason = None
        try:
            if timeout_seconds is not None:
                if type(timeout_seconds) not in (int,float) or not math.isfinite(timeout_seconds) or timeout_seconds<=0:
                    raise Stop('invalid call timeout')
                command_deadline=min(self.deadline,self.clock()+timeout_seconds)
            if max_output_bytes is not None and (type(max_output_bytes) is not int or max_output_bytes<=0):
                raise Stop('invalid call output limit')
            if max_output_bytes is not None: command_cap=min(command_cap,max_output_bytes)
            if not argv or not all(isinstance(x,str) and x and "\0" not in x for x in argv):
                raise Stop("invalid argv")
            if not Path(argv[0]).is_absolute():
                raise Stop("absolute executable required; no PATH fallback")
            if command_cap <= 0 or self.clock() >= command_deadline or self.wall_clock()>=self.calendar:
                raise Stop("budget exhausted before start")
            check_snapshot(self.backend.snapshot(), self.limits)
            # start may fail part-way; finish is still mandatory.
            started = True
            receipt["identity"] = self.backend.start(argv, cwd, env, command_deadline)
            with prefix.with_suffix(".stdout.bin").open("xb") as out, prefix.with_suffix(".stderr.bin").open("xb") as err:
                logs = {"stdout":out,"stderr":err}
                while True:
                    if self.clock() >= command_deadline or self.wall_clock()>=self.calendar:
                        raise Stop("deadline reached")
                    check_snapshot(self.backend.snapshot(), self.limits)
                    chunks = self.backend.read(min(self.limits.interval, command_deadline-self.clock()))
                    for stream, data in chunks:
                        if stream not in outputs or not isinstance(data, bytes):
                            raise Stop("invalid output event")
                        size = sum(map(len,outputs.values()))
                        allowance = min(command_cap-size, self.limits.output-self.total_output)
                        saved = data[:max(0,allowance)]
                        logs[stream].write(saved)
                        outputs[stream].extend(saved)
                        self.total_output += len(saved)
                        if len(data) > allowance:
                            receipt["observed_overflow_bytes_at_least"] = len(data)-len(saved)
                            raise Stop("output limit; retained prefix is incomplete")
                    rc = self.backend.poll()
                    if rc is not None and self.backend.eof:
                        receipt["returncode"] = rc
                        if type(rc) is not int or rc != 0:
                            raise Stop("nonzero/missing exit")
                        check_snapshot(self.backend.snapshot(), self.limits)
                        if self.clock() >= command_deadline:
                            raise Stop("deadline at exit")
                        receipt["output_complete"] = True
                        break
        except BaseException as exc:
            reason = type(exc).__name__ + ": " + str(exc)
        finally:
            if started:
                try:
                    receipt["cleanup"] = self.backend.finish(self.limits.cleanup_seconds)
                    cleanup = receipt["cleanup"]
                    receipt["returncode"] = cleanup.get("returncode", receipt["returncode"])
                    if cleanup.get("empty") is not True or cleanup.get("reaped") is not True:
                        reason = reason or "cleanup incomplete"
                    if reason is None and (type(cleanup.get('returncode')) is not int or cleanup['returncode']!=0):
                        reason = 'missing/nonzero final exit identity'
                    if cleanup.get("residual_before_cleanup"):
                        reason = reason or "leader exited leaving descendants"
                except BaseException as exc:
                    receipt["cleanup_error"] = str(exc)
                    reason = reason or "cleanup failed"
            receipt["reason"] = reason
            receipt["success"] = reason is None
            receipt["output_bytes"] = {k:len(v) for k,v in outputs.items()}
            receipt["output_sha256"] = {k:hashlib.sha256(v).hexdigest() for k,v in outputs.items()}
            receipt["global_output_bytes"] = self.total_output
            if reason:
                self.stopped = True
            try:
                exclusive_json(prefix.with_suffix(".receipt.json"), receipt)
            except BaseException:
                self.stopped = True
                raise
        if reason:
            raise Stop(reason)
        return {"returncode":0, **{k:bytes(v) for k,v in outputs.items()}}

    def patchelf_executor(self, argv, *, cwd, env, timeout_seconds, max_output_bytes):
        return self.run(argv,cwd,env,timeout_seconds,max_output_bytes)

    def close(self):
        self.stopped=True
        receipt=self.backend.close()
        exclusive_json(self.evidence/'session-close.json',receipt)
        if receipt.get('success') is not True or receipt.get('empty') is not True:
            raise Stop('session watchdog cleanup not confirmed')
        return receipt
