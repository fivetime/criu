#!/usr/bin/env python3
"""Native PSI dump admission and source-continuity regression.

Run as root only inside an independent PID, mount and cgroup namespace with
private mounts and writable cgroup v2. The caller supplies CPU/memory/PID limits.
Never run this test against an application or the host cgroup hierarchy.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time


def command(*args, **kwargs):
    return subprocess.run(args, check=True, timeout=60, **kwargs)


def status(path, process, minimum=0, checked=False):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError('fixture exited before continuity proof')
        try:
            fields = [int(x) for x in path.read_text().split()]
        except (FileNotFoundError, ValueError):
            fields = []
        if len(fields) == 5 and fields[1] > minimum and (not checked or fields[2]):
            if fields[0] != process.pid or fields[3]:
                raise RuntimeError('fixture identity or descriptor verification failed')
            return fields
        time.sleep(.02)
    raise RuntimeError('fixture progress deadline exceeded')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--criu', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    criu = str(Path(args.criu).resolve(strict=True))
    fixture = str(Path(__file__).with_name('fixture').resolve(strict=True))
    output = Path(args.output).absolute()
    output.mkdir(mode=0o700)
    cgroup = Path('/sys/fs/cgroup/psi-fd-gate')
    if os.getpid() != 1 or Path('/proc/self/cgroup').read_text().strip() != '0::/':
        raise RuntimeError('run as PID 1 in an independent cgroup namespace')
    if not Path('/sys/fs/cgroup/memory.pressure').is_file():
        raise RuntimeError('PSI and cgroup v2 are required, not skipped')
    cgroup.mkdir()
    runner = cgroup / 'runner'
    runner.mkdir()
    (runner / 'cgroup.procs').write_text(str(os.getpid()))
    (Path('/sys/fs/cgroup') / 'cgroup.subtree_control').write_text('+memory')
    (cgroup / 'cgroup.subtree_control').write_text('+memory')
    leaf = cgroup / 'leaf'
    leaf.mkdir()
    pressure = leaf / 'memory.pressure'
    proc = Path('/proc/pressure/memory')
    cases = []
    for kind, path in [('cgroup', pressure), ('proc', proc)]:
        for mode in ['rdwr-armed', 'rdwr-unarmed', 'wronly-unarmed', 'dup-armed', 'scm-armed']:
            cases.append((kind + '-' + mode, mode, path, True, None, False))
        file_alias = output / (kind + '-opaque-file')
        file_alias.touch()
        command('mount', '--bind', str(path), str(file_alias))
        cases.append((kind + '-file-bind', 'rdwr-armed', file_alias, True, None, False))
        dir_alias = output / (kind + '-opaque-directory')
        dir_alias.mkdir()
        command('mount', '--bind', str(path.parent), str(dir_alias))
        cases.append((kind + '-directory-bind', 'rdwr-armed', dir_alias / path.name, True, None, False))
        ns_alias = output / (kind + '-private-ns-alias')
        ns_alias.touch()
        cases.append((kind + '-namespace-bind', 'rdwr-armed', path, True, ns_alias, False))
        cases.append((kind + '-external-file', 'rdwr-armed', path, True, None, True))
        for mode in ['readonly', 'opath']:
            cases.append((kind + '-' + mode, mode, path, False, None, False))
    plain = output / 'memory.pressure'
    plain.write_text('ordinary file, no PSI trigger\n')
    cases.append(('ordinary-same-name', 'rdwr-unarmed', plain, False, None, False))
    cases.append(('writable-cgroup-control', 'rdwr-unarmed', leaf / 'cgroup.procs', False, None, False))
    results = []
    for name, mode, path, refused, alias, external in cases:
        directory = output / name
        directory.mkdir()
        state = directory / 'progress'
        with (directory / 'fixture.log').open('wb') as log:
            cmd = [fixture, mode, str(path), str(state)] + ([str(alias)] if alias else [])
            process = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=log,
                                       stderr=log, start_new_session=True)
            try:
                before = status(state, process)
                (leaf / 'cgroup.procs').write_text(str(process.pid))
                starttime = Path('/proc/%d/stat' % process.pid).read_text().split()[21]
                images = directory / 'images'
                images.mkdir()
                cmd = [criu, 'dump', '-t', str(process.pid), '-D', str(images), '-v4',
                       '-o', 'dump.log', '--shell-job',
                       '--external', 'mnt[]', '--manage-cgroups=ignore']
                if not refused:
                    cmd.append('--leave-running')
                if external:
                    # The PSI guard must run before the external-file shortcut.
                    fd = next(p for p in Path('/proc/%d/fd' % process.pid).iterdir()
                              if os.readlink(p) == str(path))
                    info = (Path('/proc/%d/fdinfo' % process.pid) / fd.name).read_text()
                    mount = next(int(line.split()[1]) for line in info.splitlines()
                                 if line.startswith('mnt_id:'))
                    cmd += ['--external', 'file[%x:%x]' % (mount, path.stat().st_ino)]
                result = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=log,
                                        stderr=log, timeout=60)
                dump = (images / 'dump.log').read_text()
                if refused:
                    if result.returncode == 0 or 'Unsupported writable PSI descriptor:' not in dump:
                        raise RuntimeError(name + ': missing explicit PSI refusal')
                elif result.returncode != 0 or 'Dumping finished successfully' not in dump:
                    raise RuntimeError(name + ': safe descriptor was rejected')
                after = status(state, process, before[1] + 2)
                if Path('/proc/%d/stat' % process.pid).read_text().split()[21] != starttime:
                    raise RuntimeError('source process identity changed')
                process.send_signal(signal.SIGUSR1)
                verified = status(state, process, after[1], checked=True)
                record = {'case': name, 'expected_refusal': refused,
                          'dump_exit_code': result.returncode, 'pid': process.pid,
                          'starttime': starttime, 'before': before, 'after': after,
                          'verified': verified, 'source_continuity': True,
                          'dump_log_sha256': hashlib.sha256((images / 'dump.log').read_bytes()).hexdigest()}
                (directory / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
                results.append(record)
                print('PASS ' + name, flush=True)
            finally:
                # This is only the child started above; never signal an application PID.
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=10)
    (output / 'results.json').write_text(json.dumps({
        'criu_sha256': hashlib.sha256(Path(criu).read_bytes()).hexdigest(),
        'kernel': os.uname().release, 'cases': results}, indent=2) + '\n')


if __name__ == '__main__':
    main()
