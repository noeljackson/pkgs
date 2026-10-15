#!/usr/bin/env python3
"""Publish only the checked-in, previously qualified kernel/DRBD archive pair."""
import hashlib
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
REPOSITORY = 'noeljackson/pkgs'
SOURCE = 'https://github.com/' + REPOSITORY
TARGETS = ('kernel', 'drbd-pkg')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def validate_lock(lock):
    require(set(lock) == {'schema', 'source_revision', 'release_id', 'packages'}, 'unexpected publication fields')
    require(lock['schema'] == 'wireguard.package-publication/v1', 'wrong publication schema')
    require(re.fullmatch('[0-9a-f]{40}', lock['source_revision']), 'full source revision required')
    require(type(lock['release_id']) is int and lock['release_id'] > 0, 'invalid transfer release')
    require(set(lock['packages']) == set(TARGETS), 'only the paired final packages are allowed')
    for target, package in lock['packages'].items():
        require(set(package) == {'asset_id', 'archive_sha256', 'manifest'}, 'unexpected package fields')
        require(type(package['asset_id']) is int and package['asset_id'] > 0, 'invalid transfer asset')
        require(re.fullmatch('[0-9a-f]{64}', package['archive_sha256']), 'invalid archive checksum')
        require(re.fullmatch('sha256:[0-9a-f]{64}', package['manifest']), 'invalid package digest')


def require_context(env, head, clean, source_is_ancestor):
    require(env.get('GITHUB_ACTIONS') == 'true' and env.get('GITHUB_EVENT_NAME') == 'push', 'push workflow required')
    require(env.get('GITHUB_REPOSITORY') == REPOSITORY, 'wrong source repository')
    require(env.get('GITHUB_REF') == 'refs/heads/ams-fra-throughput', 'wrong source branch')
    require(re.fullmatch('[0-9a-f]{40}', head) and env.get('GITHUB_SHA') == head, 'event/checkout mismatch')
    require(clean and source_is_ancestor, 'clean source and qualified ancestor required')


def destination(target, digest):
    require(target in TARGETS and re.fullmatch('sha256:[0-9a-f]{64}', digest), 'invalid publication destination')
    # A digest destination cannot replace a different manifest under a tag.
    return 'ghcr.io/' + REPOSITORY.split('/')[0] + '/' + target + '@' + digest


def unpack(archive_path, layout, expected_sha):
    require(sha(archive_path) == expected_sha, 'archive checksum differs')
    # OCI-archive transport tries to restore UID 0 under rootless Skopeo.
    # Materialize only verified OCI files, without restoring archive ownership.
    require(not layout.exists() and not layout.is_symlink(), 'layout already exists')
    layout.mkdir(mode=0o700)
    seen = set()
    try:
        with tarfile.open(archive_path, 'r') as archive:
            total = 0
            for member in archive:
                name = member.name.rstrip('/')
                require(name not in seen, 'duplicate archive member')
                seen.add(name)
                require(name in {'oci-layout', 'index.json', 'blobs', 'blobs/sha256'}
                        or re.fullmatch('blobs/sha256/[0-9a-f]{64}', name), 'unexpected archive path')
                path = layout / name
                if member.isdir():
                    require(name in {'blobs', 'blobs/sha256'}, 'unexpected directory')
                    path.mkdir(mode=0o700, parents=True, exist_ok=True)
                    continue
                total += member.size
                require(member.isfile() and 0 <= member.size <= 128 * 1024**2
                        and total <= 256 * 1024**2, 'invalid or oversized archive member')
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with archive.extractfile(member) as source, path.open('xb') as output:
                    shutil.copyfileobj(source, output)
                path.chmod(0o600)
                if name.startswith('blobs/sha256/'):
                    require(sha(path) == path.name, 'blob digest differs')
    except BaseException:
        shutil.rmtree(layout)
        raise


def inspect_layout(layout, target, revision, manifest_digest):
    def read_descriptor(desc):
        require(re.fullmatch('sha256:[0-9a-f]{64}', desc['digest']), 'invalid descriptor')
        path = layout / 'blobs/sha256' / desc['digest'].split(':')[1]
        require(path.stat().st_size == desc['size'] and 'sha256:' + sha(path) == desc['digest'], 'descriptor mismatch')
        return json.loads(path.read_text())
    require(json.loads((layout / 'oci-layout').read_text()) == {'imageLayoutVersion': '1.0.0'}, 'invalid OCI layout')
    index = json.loads((layout / 'index.json').read_text())
    require(index.get('schemaVersion') == 2 and len(index.get('manifests', [])) == 1, 'one platform required')
    descriptor = index['manifests'][0]
    require(descriptor['digest'] == manifest_digest and descriptor.get('platform') == {'architecture': 'amd64', 'os': 'linux'}, 'wrong manifest/platform')
    manifest = read_descriptor(descriptor)
    require(manifest.get('schemaVersion') == 2 and manifest.get('layers'), 'invalid package manifest')
    config = read_descriptor(manifest['config'])
    require(config.get('architecture') == 'amd64' and config.get('os') == 'linux', 'wrong config platform')
    labels = config.get('config', {}).get('Labels', {})
    for key, value in {'source': SOURCE, 'revision': revision, 'title': target}.items():
        require(labels.get('org.opencontainers.image.' + key) == value, 'wrong package ' + key)
    for layer in manifest['layers']:
        require(not layer.get('urls'), 'external layers are forbidden')
        path = layout / 'blobs/sha256' / layer['digest'].removeprefix('sha256:')
        require(re.fullmatch('sha256:[0-9a-f]{64}', layer['digest'])
                and path.stat().st_size == layer['size'] and 'sha256:' + sha(path) == layer['digest'], 'layer mismatch')


def main():
    os.umask(0o077)
    lock = json.loads((HERE / 'publication.json').read_text())
    validate_lock(lock)
    git = lambda *args: subprocess.check_output(['git', *args], cwd=ROOT, text=True).strip()
    source = lock['source_revision']
    ancestor = subprocess.run(['git', 'merge-base', '--is-ancestor', source, 'HEAD'], cwd=ROOT).returncode == 0
    require_context(os.environ, git('rev-parse', 'HEAD'), not git('status', '--porcelain'), ancestor)
    api = lambda path: json.loads(subprocess.check_output(['gh', 'api', 'repos/' + REPOSITORY + '/' + path], timeout=60))
    release = api('releases/' + str(lock['release_id']))
    require(release['draft'] is True and release['target_commitish'] == source
            and release['tag_name'] == 'ams-fra-transfer-' + source, 'wrong transfer release')
    assets = {asset['name']: asset['id'] for asset in release['assets']}
    require(assets == {target + '.oci.tar': lock['packages'][target]['asset_id'] for target in TARGETS}, 'transfer assets differ')
    receipts = []
    with tempfile.TemporaryDirectory(prefix='wireguard-package-publish-') as temp:
        temp = Path(temp)
        # Verify both packages completely before the first registry write.
        for target in TARGETS:
            package = lock['packages'][target]
            archive = temp / (target + '.oci.tar')
            with archive.open('xb') as output:
                subprocess.run(['gh', 'api', '-H', 'Accept: application/octet-stream',
                                'repos/' + REPOSITORY + '/releases/assets/' + str(package['asset_id'])],
                               stdout=output, check=True, timeout=180)
            unpack(archive, temp / target, package['archive_sha256'])
            inspect_layout(temp / target, target, source, package['manifest'])
        authfile = str(Path(os.environ['DOCKER_CONFIG']) / 'config.json')
        for target in TARGETS:
            package = lock['packages'][target]
            ref = destination(target, package['manifest'])
            subprocess.run(['skopeo', '--command-timeout', '5m', 'copy', '--src-no-creds',
                            '--dest-authfile', authfile, '--preserve-digests',
                            'oci:' + str(temp / target), 'docker://' + ref], check=True, timeout=330)
            raw = subprocess.check_output(['skopeo', 'inspect', '--raw', '--authfile', authfile, 'docker://' + ref], timeout=60)
            require('sha256:' + hashlib.sha256(raw).hexdigest() == package['manifest'], 'published digest differs')
            receipts.append(dict(reference=ref, manifest=package['manifest'], source_revision=source,
                                 archive_sha256=package['archive_sha256'], public_access_verified=False))
    text = json.dumps(receipts, indent=2)
    print(text)
    with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as summary:
        summary.write('Verified package publication (public visibility remains a separate check):\n```json\n' + text + '\n```\n')


if __name__ == '__main__':
    main()
