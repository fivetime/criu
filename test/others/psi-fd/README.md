# PSI descriptor dump admission

The kernel does not expose the trigger state associated with an open PSI file
description. CRIU therefore refuses writable proc/cgroup-v2 pressure descriptors,
including those that have not yet been armed. This prevents a successful-looking
restore from replacing an armed trigger with a permanently error-ready file.
This suite tests that refusal and the continued health of the original process;
it does **not** qualify restoration of PSI triggers.

## Run

Build CRIU and this fixture, then execute the test **inside a disposable, privileged
container with private PID, mount and cgroup namespaces, no network or host bind
mounts, and CPU, memory and PID limits**. Do not run it on the host. The container
must provide writable cgroup v2 with the memory controller and PSI enabled. It
needs a C compiler, Python 3, the `mount` command, and the freshly built CRIU binary.

```sh
make -C test/others/psi-fd
# In that isolated container, as its initial process (PID 1):
exec python3 test/others/psi-fd/run.py \
    --criu ./criu/criu --output /tmp/psi-fd-results
```

The output directory must not exist. Example container limits are two CPUs,
2 GiB memory, 2 GiB combined memory/swap, and 1024 PIDs. This test intentionally
does not request privileges or start containers itself, and is not added to
unprivileged CI jobs. Missing PSI or isolation prerequisites fail explicitly.

The 24 cases cover armed and unarmed writable descriptors, write-only opens,
`dup`, queued `SCM_RIGHTS` after the sender closes its descriptor, file and
directory bind aliases, private mount namespaces, and the external-file shortcut.
Read-only statistics, `O_PATH`, an ordinary file named `memory.pressure`, and a
writable `cgroup.procs` file remain admissible.

Each case requests a real dump. The refusal cases deliberately omit
`--leave-running`, matching an ordinary destructive checkpoint request. A refusal
must have the specific PSI diagnostic, and the original PID, `/proc` start time and progress
counter must continue. Armed descriptors are also checked for error-free polling
and `EBUSY` on a second trigger write; queued descriptors are received and checked
only after the dump. The safe cases use `--leave-running` and must produce a successful dump. Full positive
checkpoint/restore remains covered separately by ZDTM `cgroupv2_fds` and its deep
and namespace variants, using read-only pressure descriptors, plus the ordinary
`opath_file` and SCM tests.

`results.json`, per-case `result.json`, `progress`, `fixture.log` and
`images/dump.log` are retained. The runner terminates only its own fixture child.
It leaves its exact cgroups, aliases and evidence for the disposable container's
owner to inspect and remove; it never scans or cleans host resources.
