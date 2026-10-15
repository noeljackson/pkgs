# WireGuard batching reproducer

This is source-level verification for patches 0017–0020, using the upstream
Linux 6.18.48 WireGuard selftest initramfs. It does not qualify a Talos image,
Cilium configuration, physical NIC, Internet path or production rollout.

Use Linux 6.18.48 from the exact `Pkgfile` checksum. Build the unchanged
upstream WireGuard QEMU fixture once from baseline source and once with these
four patches. The upstream Makefile pins and verifies its userspace inputs:

```sh
make -C "$linux_source/tools/testing/selftests/wireguard/qemu" \
  ARCH=x86_64 NR_CPUS=8 BUILD_PATH="$private_build" \
  DISTFILES_PATH="$private_distfiles" build
```

Keep baseline and candidate source/build directories separate. The kernel must
embed the upstream `init` and unchanged `netns.sh`, with Bash, iproute2, iperf
3.11, iptables-legacy, ping, ncat and wg. Enable `CONFIG_VIRTIO_NET=y` in both
minimal kernel configurations and rebuild for wire mode; retain the upstream
x86_64 microvm/virtio-console configuration and `CONFIG_HOTPLUG_CPU=y`.

The recorded 2026-10-15 runs used a native fixture after the pinned upstream
cross-toolchain mirror timed out: trusted host binaries and their runtime
libraries, iperf 3.11 built from its upstream Git tag, and a copied upstream
`init.c` using `clock_settime` instead of `stime` for glibc compatibility.
`netns.sh` was unchanged. The private evidence retains the userspace file
manifest, init source, exact kernel configurations and archive checksums.
These native-fixture receipts do not claim that the upstream cross-toolchain
build command succeeded. Reuse identical userspace and configuration for both
kernels in a comparison, and record any fixture adaptation explicitly.

Keep `CONFIG_WIREGUARD_DEBUG=y` in the test kernels. Patch 0020 adds eleven
module-admission checks around the actual TX batching helper: complete record
bytes, GSO/checksum metadata, flow hashes/flags, DS/ECN, record lengths,
isolated packets, keepalives, count/byte bounds and the retained next flow.
The initial draft fails four hash-affinity cases; the corrected batcher must
print `UDP batch self-tests (11 cases): pass` before the ordinary suite runs.
Production configuration remains unchanged and excludes these debug tests.

Run the unchanged upstream suite, then matched 120-second namespace tests:

```sh
python3 hack/wireguard-throughput/run-vm.py --mode regression \
  --kernel "$candidate_bzimage" --require-batch-selftest --out "$private_results"
python3 hack/wireguard-throughput/run-vm.py --mode namespace \
  --kernel "$baseline_bzimage" --out "$private_results"
python3 hack/wireguard-throughput/run-vm.py --mode namespace \
  --kernel "$candidate_bzimage" --require-batch-selftest --out "$private_results"
```

The namespace fixture uses four TCP flows, MTU1370, three seconds of warmup and
120 measured seconds in each direction. It creates random disposable keys
inside the VM. Its transport is loopback within that kernel, so these rates
must be reported separately from NIC or production rates.

Wire mode runs two VMs connected only through a private Unix socket. It adds
20-second plaintext controls, 120-second encrypted IPv4 measurements,
10-second IPv6 interoperability tests, and a CPU-offline/restore check after
isolated packets have advanced the receive worker. Run baseline/baseline,
candidate/baseline and candidate/candidate when qualifying the final source:

```sh
python3 hack/wireguard-throughput/run-vm.py --mode wire \
  --kernel "$candidate_bzimage" --peer-kernel "$baseline_bzimage" \
  --require-batch-selftest --out "$private_results"
```

Wire mode uses publicly known synthetic fixture keys. It never connects a VM
to host IP networking. Inspect plaintext controls before interpreting the
virtual NIC's throughput; the backend can constrain the experiment. Record
host contention as well: unrelated compilation invalidates a controlled rate
comparison even when protocol/cleanup assertions pass. The
iptables counters demonstrate that both outer ingress policy paths execute.
The standard UDP layer segments aggregates before WireGuard authentication.

Each VM has 4 GiB RAM, an independent 500-second timeout, no disk, no reboot,
and a required upstream `success` marker. Namespace/regression mode uses eight
vCPUs; wire mode uses four per VM. Output must be caller-owned mode 0700.
Unique receipts bind kernel and fixture hashes, commands, exit status and
iperf JSON. Failures retain logs and terminate owned processes. Avoid other
CPU-intensive work during performance comparisons. Remove disposable images,
logs and build trees after preserving the required result/provenance records.

The TX GSO patch preserves each encrypted wire record and the per-peer
ciphertext byte total. Generic tunnel netdevice TX packet counters now count
GSO skbs, and UDP-header overhead is counted per aggregate before segmentation.
Use physical NIC wire counters for packet conservation; do not interpret a
lower WireGuard netdevice TX packet count as packet loss.

The production artifact path additionally requires source-owned immutable
packages, DRBD signed by the matching kernel build, enforcing Talos direct and
staged-upgrade QEMU gates, serial node rollout and sustained live acceptance.
See infra's `docs/runbooks/talos-artifact-debugging.md` and issue #1430.

## Paired production packages

`package-candidate.py` builds only final `kernel` and `drbd-pkg` OCI archives,
sequentially in the same private builder cache. It requires a clean signed
source commit and a task-owned single-node Docker Buildx v0.36.1 builder using
BuildKit `moby/buildkit@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8`,
with a six-CPU quota and 24 GiB memory/swap limit. Each build has a 90-minute
bound. Use a new private output path outside this checkout:

```sh
python3 hack/wireguard-throughput/test-finalize-package-oci.py
python3 hack/wireguard-throughput/package-candidate.py \
  --builder "$task_builder" --buildx "$pinned_buildx_binary" \
  --builder-config "$task_buildx_state_directory" \
  --output "$new_private_output"
```

The provided linux-amd64 Buildx binary must match SHA-256
`48af8a397ebd60178778bf63611dbcebe5f5e7a9be90eb9147b24b9587455778`.
It is copied into the new anonymous Docker configuration's plugin directory,
so changing credential configuration cannot select an older ambient plugin.
The separate task-owned Buildx state directory selects the already-running
builder; it is not used as the Docker registry credential configuration.
Inputs use that anonymous Docker configuration and a minimal environment;
ambient make, registry and package overrides are not forwarded. The wrapper
never publishes, exports a build cache, or selects the `kernel-build` stage.
That private cache contains the generated module-signing key: keep it private
and remove the task-owned builder/cache after preserving the final packages
and required evidence.

The package frontend has static OCI labels. The included finalizer therefore
adds the source-owner URL and full Git revision to each final OCI configuration
after export. It verifies the input descriptors and layer hashes, copies every
filesystem layer unchanged, and records the new image identity. Its seven
synthetic tests cover payload/metadata integrity and refusal of intermediate
targets, abbreviated revisions, corrupt/duplicate inputs, different platforms
and existing output paths. No literal build-argument template is used as a
revision label.

The archive inspection checks the release and signing metadata of mlx5,
virtio-net and all four DRBD modules, and requires one signing key identity
across the pair. This is not cryptographic module-load or runtime acceptance;
the exact enforcing Talos boot and lifecycle gates remain mandatory. Source
publication and new package destinations need their own admitted transaction.
