#!/usr/bin/env python3
"""Build local, source-labelled kernel/DRBD OCI archives; never publish."""
import argparse
import datetime
import hashlib
import importlib.util
import sys
sys.dont_write_bytecode = True
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BUILDKIT = 'moby/buildkit@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8'
BUILDX = 'v0.36.1'
BUILDX_SHA256 = '48af8a397ebd60178778bf63611dbcebe5f5e7a9be90eb9147b24b9587455778'
RELEASE = '6.18.48-talos'
TARGETS = ('kernel', 'drbd-pkg')
spec = importlib.util.spec_from_file_location('finalizer', HERE / 'finalize-package-oci.py')
finalizer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(finalizer)


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as source:
        while block := source.read(1024 * 1024):
            h.update(block)
    return h.hexdigest()


def inspect_modules(archive_path, target, temporary):
    expected = ({'mlx5_core.ko', 'virtio_net.ko'} if target == 'kernel' else
                {'drbd.ko', 'drbd_transport_tcp.ko', 'drbd_transport_lb-tcp.ko', 'drbd_transport_rdma.ko'})
    found = {}
    with tarfile.open(archive_path, 'r:*') as archive:
        index = json.load(archive.extractfile('index.json'))
        manifest = json.load(archive.extractfile(finalizer.blob_name(index['manifests'][0])))
        for layer in manifest['layers']:
            with archive.extractfile(finalizer.blob_name(layer)) as compressed, tarfile.open(fileobj=compressed, mode='r|*') as files:
                for member in files:
                    name = Path(member.name).name
                    if name not in expected:
                        continue
                    if (name in found or not member.isfile() or member.size > 32 * 1024 * 1024
                            or not member.name.lstrip('./').startswith('usr/lib/modules/' + RELEASE + '/')):
                        raise ValueError('unexpected module member')
                    local = temporary / (target + '-' + name)
                    with files.extractfile(member) as source, local.open('xb') as output:
                        output.write(source.read())
                    values = {field: subprocess.check_output(['modinfo', '-F', field, str(local)], text=True).strip()
                              for field in ('vermagic', 'signer', 'sig_key', 'sig_hashalgo')}
                    if (values['vermagic'].split()[0] != RELEASE or not values['signer']
                            or not values['sig_key'] or values['sig_hashalgo'] != 'sha512'):
                        raise ValueError('unsigned module or unexpected release/signature algorithm')
                    found[name] = dict(sha256=sha(local), **values)
                    local.unlink()
    if set(found) != expected:
        raise ValueError('required modules missing from final package')
    return found


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--builder', required=True, help='existing task-owned pinned docker-container builder')
    parser.add_argument('--builder-config', required=True, type=Path, help='task-owned Buildx state directory, separate from registry credentials')
    parser.add_argument('--buildx', required=True, type=Path, help='checksum-pinned v0.36.1 linux-amd64 plugin binary')
    parser.add_argument('--output', required=True, type=Path, help='new private directory outside the source checkout')
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', args.builder):
        raise ValueError('invalid builder name')
    git = lambda *items: subprocess.check_output(['git', *items], cwd=ROOT, text=True).strip()
    if git('status', '--porcelain', '--untracked-files=all') or git('ls-files', '--others', '--ignored', '--exclude-standard'):
        raise ValueError('clean source, including ignored build inputs, is required')
    revision = git('rev-parse', 'HEAD')
    subprocess.run(['git', 'verify-commit', revision], cwd=ROOT, check=True, capture_output=True)
    output = args.output.resolve()
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+', str(output)):
        raise ValueError('output path must use plain filesystem characters')
    if output == ROOT or ROOT in output.parents or not output.parent.is_dir():
        raise ValueError('output needs an existing parent outside the checkout')
    output.mkdir(mode=0o700)
    docker_config = output / 'anonymous-docker'
    docker_config.mkdir(mode=0o700)
    (docker_config / 'config.json').write_text(json.dumps({'auths': {'https://index.docker.io/v1/': {}, 'ghcr.io': {}}}))
    if sha(args.buildx) != BUILDX_SHA256:
        raise ValueError('Buildx binary checksum differs')
    plugins = docker_config / 'cli-plugins'
    plugins.mkdir(mode=0o700)
    shutil.copyfile(args.buildx, plugins / 'docker-buildx')
    (plugins / 'docker-buildx').chmod(0o700)
    env = {key: os.environ[key] for key in ('PATH', 'HOME', 'USER', 'LOGNAME', 'LANG') if key in os.environ}
    env.update(DOCKER_CONFIG=str(docker_config), BUILDX_BUILDER=args.builder,
               BUILDX_CONFIG=str(args.builder_config.resolve(strict=True)))
    call = lambda *items: subprocess.check_output(items, cwd=ROOT, env=env, text=True, timeout=30).strip()
    version = call('docker', 'buildx', 'version').split()
    if len(version) < 2 or version[1] != BUILDX:
        raise ValueError('unexpected Buildx version')
    inspection = call('docker', 'buildx', 'inspect', args.builder)
    if not re.search(r'^Driver:\s+docker-container$', inspection, re.M) or len(re.findall(r'^Endpoint:', inspection, re.M)) != 1:
        raise ValueError('one private docker-container builder node is required')
    container = 'buildx_buildkit_' + args.builder + '0'
    fields = call('docker', 'inspect', '--format', '{{.Config.Image}} {{.HostConfig.Memory}} {{.HostConfig.MemorySwap}} {{.HostConfig.CpuPeriod}} {{.HostConfig.CpuQuota}}', container).split()
    if fields != [BUILDKIT, str(24 * 1024**3), str(24 * 1024**3), '100000', '600000']:
        raise ValueError('builder image or six-CPU/24-GiB resource limits differ')
    record = dict(schema='wireguard.package-candidate/v1', source=finalizer.SOURCE, revision=revision,
                  buildkit=BUILDKIT, buildx=BUILDX, builder=args.builder, platform='linux/amd64',
                  commands=[], packages={}, claims={'publication': False, 'runtime_acceptance': False})
    try:
        for target in TARGETS:
            raw = output / (target + '-raw.oci.tar')
            metadata = output / (target + '-buildkit.json')
            command = ['make', 'target-' + target, 'BUILD=docker buildx build --builder ' + args.builder,
                       'PLATFORM=linux/amd64', 'PUSH=false', 'PROGRESS=plain',
                       'TARGET_ARGS=--output=type=oci,dest=' + str(raw) + ' --metadata-file=' + str(metadata)]
            entry = dict(argv=command, started=datetime.datetime.now(datetime.timezone.utc).isoformat())
            record['commands'].append(entry)
            with (output / (target + '.log')).open('x') as log:
                result = subprocess.run(['timeout', '--signal=TERM', '--kill-after=30', '5400', *command],
                                        cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
            entry.update(exit_code=result.returncode, ended=datetime.datetime.now(datetime.timezone.utc).isoformat())
            if result.returncode:
                raise RuntimeError('package build failed: ' + target)
            labelled = output / (target + '.oci.tar')
            package = finalizer.finalize(raw, labelled, revision, target)
            package.update(raw_sha256=sha(raw), labelled_sha256=sha(labelled))
            with tempfile.TemporaryDirectory(prefix='module-inspection-', dir=output) as temp:
                package['modules'] = inspect_modules(labelled, target, Path(temp))
            record['packages'][target] = package
            print(target + ' local archive inspected', flush=True)
        keys = {module['sig_key'] for package in record['packages'].values() for module in package['modules'].values()}
        if len(keys) != 1:
            raise ValueError('kernel and DRBD signing keys differ')
        if git('rev-parse', 'HEAD') != revision or git('status', '--porcelain', '--untracked-files=all'):
            raise ValueError('source changed during package build')
        record.update(success=True, signing_metadata_matches=True,
                      note='Metadata and unchanged-layer inspection only; enforcing Talos module-load and lifecycle acceptance remain required.')
    except BaseException as error:
        record.update(success=False, error=str(error))
        raise
    finally:
        with (output / 'result.json').open('x') as stream:
            json.dump(record, stream, indent=2)
            stream.write('\n')
        print(output / 'result.json', flush=True)


if __name__ == '__main__':
    main()
