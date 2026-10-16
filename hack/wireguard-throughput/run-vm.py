#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Bounded source-level WireGuard regression/performance VMs; no host IP network."""
import argparse
import datetime
import hashlib
import json
import os
import signal
from pathlib import Path
import subprocess
import tempfile
import time
import uuid


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def overlay(script):
    """Override only /init.sh in the upstream WireGuard QEMU initramfs."""
    payload = script.read_bytes()
    output = b""
    for inode, name, mode, data in [(1, b"init.sh\0", 0o100755, payload),
                                    (2, b"TRAILER!!!\0", 0, b"")]:
        fields = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name), 0]
        output += b"070701" + b"".join(f"{v:08x}".encode() for v in fields) + name
        output += b"\0" * (-len(output) % 4)
        output += data
        output += b"\0" * (-len(output) % 4)
    return output + b"\0" * (-len(output) % 512)


def parse_vxlan_results(text, expect_batching):
    """Require the complete nested-tunnel matrix and observed TX batching."""
    if expect_batching not in {"enabled", "disabled"}:
        raise ValueError("VXLAN batching expectation is required")
    if "VXLAN_FIXTURE_COMPLETE" not in text:
        raise ValueError("VXLAN fixture did not finish")
    expected = {
        f"wg{wire}-vx{vxlan}-{checksum}-tcp{inner}-{direction}"
        for wire in (4, 6)
        for vxlan in (4, 6)
        for checksum in (("udpcsum", "noudpcsum") if vxlan == 4 else ("default6",))
        for inner in (4, 6)
        for direction in ("forward", "reverse")
    }
    links, rates = {}, {}
    for chunk in text.split("BEGIN_LINK ")[1:]:
        case, when = chunk.splitlines()[0].split()
        key = (case, when)
        if case not in expected or when not in {"before", "after"} or key in links:
            raise ValueError("unexpected or duplicate VXLAN link capture")
        value, _ = json.JSONDecoder().raw_decode(chunk[chunk.index("["):])
        if len(value) != 1 or value[0]["ifname"] != "wg0":
            raise ValueError("wrong VXLAN counter interface")
        links[key] = value[0]["stats64"]["tx"]
    for chunk in text.split("BEGIN_VXLAN ")[1:]:
        case = chunk.splitlines()[0].split()[0]
        if case not in expected or case in rates:
            raise ValueError("unexpected or duplicate VXLAN transfer")
        value, _ = json.JSONDecoder().raw_decode(chunk[chunk.index("{"):])
        if "error" in value:
            raise ValueError(value["error"])
        received = value["end"]["sum_received"]
        if received["bytes"] <= 0 or received["seconds"] < 4.5 or received["bits_per_second"] <= 0:
            raise ValueError("incomplete VXLAN transfer")
        rates[case] = received
    if set(rates) != expected or set(links) != {(case, when) for case in expected for when in ("before", "after")}:
        raise ValueError("incomplete VXLAN matrix")
    results = []
    for case in sorted(expected):
        before, after = links[(case, "before")], links[(case, "after")]
        packets, count = after["packets"] - before["packets"], after["bytes"] - before["bytes"]
        if packets <= 0 or count <= 0:
            raise ValueError("non-progressing VXLAN counters")
        mean = count / packets
        if expect_batching == "enabled" and mean <= 4096:
            raise ValueError(f"encrypted batching missing: {case} ({mean:.1f} bytes/skb)")
        if expect_batching == "disabled" and mean >= 2000:
            raise ValueError(f"baseline already batches: {case} ({mean:.1f} bytes/skb)")
        results.append(dict(case=case, received=rates[case], wg_tx_packets=packets,
                            wg_tx_bytes=count, mean_bytes_per_wg_tx_skb=mean))
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["regression", "namespace", "wire", "vxlan"], required=True)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--peer-kernel", type=Path)
    parser.add_argument("--require-batch-selftest", action="store_true",
                        help="require all eleven batch checks in the main kernel")
    parser.add_argument("--expect-vxlan-batching", choices=["enabled", "disabled"],
                        help="required for VXLAN mode; qualify both baseline and candidate")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if bool(args.peer_kernel) != (args.mode == "wire"):
        parser.error("--peer-kernel is required only for wire mode")
    if bool(args.expect_vxlan_batching) != (args.mode == "vxlan"):
        parser.error("--expect-vxlan-batching is required only for vxlan mode")
    os.umask(0o077)
    args.out.mkdir(parents=True, exist_ok=True, mode=0o700)
    if args.out.stat().st_uid != os.getuid() or args.out.stat().st_mode & 0o077:
        parser.error("output directory must be owned by the caller and mode 0700")
    out = args.out.resolve()
    tag = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + args.mode + "-" + uuid.uuid4().hex[:8]
    metadata = {"mode": args.mode, "cpus_per_vm": 4 if args.mode == "wire" else 8,
                "memory_per_vm": "4GiB", "timeout_seconds": 500, "peers": {}}
    metadata.update(runner_sha256=sha(Path(__file__)),
                    require_batch_selftest=args.require_batch_selftest,
                    expect_vxlan_batching=args.expect_vxlan_batching)
    procs, handles = [], []
    try:
        with tempfile.TemporaryDirectory(prefix="wg-perf-") as temporary:
            short = Path(temporary)
            sock = short / "wire.sock"
            initrd = None
            if args.mode != "regression":
                script = Path(__file__).with_name(args.mode + "-init.sh")
                initrd = out / (tag + "-init.cpio")
                initrd.write_bytes(overlay(script))
                metadata.update(fixture_sha256=sha(script), initrd_sha256=sha(initrd))
            pairs = [("server", args.peer_kernel), ("client", args.kernel)] if args.mode == "wire" else [("client", args.kernel)]
            for role, kernel in pairs:
                kernel = kernel.resolve(strict=True)
                log, result = out / (tag + "-" + role + ".log"), out / (tag + "-" + role + ".result")
                handle = log.open("x")
                handles.append(handle)
                command = ["timeout", "--foreground", "500", "qemu-system-x86_64", "-nodefaults", "-nographic", "-smp", str(metadata["cpus_per_vm"]), "-cpu", "host", "-machine", "microvm,accel=kvm,pit=off,pic=off,rtc=off,acpi=off", "-m", "4G", "-serial", "stdio", "-chardev", f"file,path={result},id=result", "-device", "virtio-serial-device", "-device", "virtserialport,chardev=result", "-no-reboot", "-monitor", "none", "-kernel", str(kernel)]
                if initrd:
                    command += ["-initrd", str(initrd)]
                if args.mode == "wire":
                    command += ["-append", f"console=ttyS0 wg.success=vport0p1 panic_on_warn=1 reboot=t wg.role={role}", "-netdev", f"stream,id=n0,server={'on' if role == 'server' else 'off'},addr.type=unix,addr.path={sock}", "-device", "virtio-net-device,netdev=n0,mac=52:54:00:12:34:" + ("02" if role == "server" else "01")]
                proc = subprocess.Popen(command, stdout=handle, stderr=subprocess.STDOUT, start_new_session=True)
                procs.append(proc)
                metadata["peers"][role] = {"kernel": str(kernel), "kernel_sha256": sha(kernel), "pid": proc.pid, "argv": command, "log": str(log), "result": str(result)}
                if role == "server":
                    deadline = time.monotonic() + 5
                    while not sock.exists():
                        if proc.poll() is not None or time.monotonic() >= deadline:
                            raise RuntimeError("server Unix socket did not become ready")
                        time.sleep(0.05)
            (out / (tag + "-admission.json")).write_text(json.dumps(metadata, indent=2) + "\n")
            for proc in reversed(procs):
                proc.wait(timeout=505)
                if proc.returncode:
                    raise RuntimeError(f"VM exited {proc.returncode}; inspect preserved logs")
            for role, record in metadata["peers"].items():
                if Path(record["result"]).read_text() != "success\n":
                    raise RuntimeError(f"{role} lacks upstream init success marker")
            if args.require_batch_selftest:
                text = Path(metadata["peers"]["client"]["log"]).read_text()
                if "UDP batch self-tests (11 cases): pass" not in text:
                    raise RuntimeError("the main kernel lacks batch selftest acceptance")
            if args.mode == "vxlan":
                text = Path(metadata["peers"]["client"]["log"]).read_text().replace("\0", "")
                metadata["measurements"] = parse_vxlan_results(text, args.expect_vxlan_batching)
            elif args.mode != "regression":
                text = Path(metadata["peers"]["client"]["log"]).read_text().replace("\0", "")
                marker = "BEGIN_WIRE " if args.mode == "wire" else "BEGIN_SUSTAINED "
                rates = []
                for chunk in text.split(marker)[1:]:
                    data, _ = json.JSONDecoder().raw_decode(chunk[chunk.index("{"):])
                    if "error" in data:
                        raise RuntimeError(data["error"])
                    rates.append({"direction": chunk.split()[0], "end": data["end"]})
                expected = {"forward", "reverse", "forward6", "reverse6", "raw-forward", "raw-reverse"} if args.mode == "wire" else {"forward", "reverse"}
                if {r["direction"] for r in rates} != expected or len(rates) != len(expected):
                    raise RuntimeError("incomplete measurement set")
                if args.mode == "wire":
                    if "HOTPLUG_PASS" not in text:
                        raise RuntimeError("CPU hotplug acceptance is missing")
                    for record in metadata["peers"].values():
                        if "POLICY_PASS" not in Path(record["log"]).read_text():
                            raise RuntimeError("outer ingress policy counters are missing")
                metadata["measurements"] = rates
            metadata["success"] = True
    except Exception as error:
        metadata.update(success=False, error=str(error))
        raise
    finally:
        for proc in procs:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=5)
        for handle in handles:
            handle.close()
        metadata["exit_codes"] = [p.returncode for p in procs]
        result = out / (tag + "-result.json")
        with result.open("x") as handle:
            json.dump(metadata, handle, indent=2)
            handle.write("\n")
        print(result, flush=True)


if __name__ == "__main__":
    main()
