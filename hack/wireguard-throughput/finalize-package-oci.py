#!/usr/bin/env python3
"""Label a final linux/amd64 package without modifying any filesystem layer.

Only the closed kernel/drbd-pkg targets are admitted. No extraction, registry,
credential, cache export or arbitrary destination is involved.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile

INDEX = 'application/vnd.oci.image.index.v1+json'
MANIFEST = 'application/vnd.oci.image.manifest.v1+json'
CONFIG = 'application/vnd.oci.image.config.v1+json'
SOURCE = 'https://github.com/noeljackson/pkgs'


def encode(value):
    return json.dumps(value, separators=(',', ':'), sort_keys=True).encode()


def descriptor(data, media_type):
    return dict(mediaType=media_type, size=len(data),
                digest='sha256:' + hashlib.sha256(data).hexdigest())


def blob_name(desc):
    digest = desc['digest']
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
        raise ValueError('invalid blob digest')
    return 'blobs/sha256/' + digest.split(':')[1]


def finalize(source, destination, revision, target):
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('a full source revision is required')
    if target not in {'kernel', 'drbd-pkg'}:
        raise ValueError('only final kernel and drbd-pkg targets are permitted')
    if destination.exists() or destination.is_symlink():
        raise ValueError('destination already exists')
    with tarfile.open(source, 'r:*') as archive:
        members = archive.getmembers()
        by_name = {m.name: m for m in members}
        if len(by_name) != len(members):
            raise ValueError('duplicate archive member')

        def read(name, maximum=16 * 1024 * 1024):
            member = by_name[name]
            if not member.isfile() or member.size > maximum:
                raise ValueError('invalid metadata member')
            return archive.extractfile(member).read()

        def read_blob(desc):
            data = read(blob_name(desc))
            if descriptor(data, desc['mediaType']) != {k: desc[k] for k in ('mediaType', 'size', 'digest')}:
                raise ValueError('metadata digest or size mismatch')
            return json.loads(data)

        if json.loads(read('oci-layout')) != {'imageLayoutVersion': '1.0.0'}:
            raise ValueError('invalid OCI layout')
        index = json.loads(read('index.json'))
        if index.get('schemaVersion') != 2 or len(index.get('manifests', [])) != 1:
            raise ValueError('one platform manifest is required')
        md = index['manifests'][0]
        if md.get('mediaType') != MANIFEST or md.get('platform', {}) != {'architecture': 'amd64', 'os': 'linux'}:
            raise ValueError('only a final linux/amd64 image is permitted')
        manifest = read_blob(md)
        if manifest.get('schemaVersion') != 2 or manifest.get('mediaType') != MANIFEST or manifest['config']['mediaType'] != CONFIG:
            raise ValueError('invalid image manifest')
        config = read_blob(manifest['config'])
        if config.get('architecture') != 'amd64' or config.get('os') != 'linux':
            raise ValueError('image platform mismatch')
        original_layers = manifest['layers']
        if not original_layers:
            raise ValueError('empty package')
        labels = config.setdefault('config', {}).setdefault('Labels', {})
        labels.update({'org.opencontainers.image.source': SOURCE,
                       'org.opencontainers.image.revision': revision,
                       'org.opencontainers.image.title': target})
        config_data = encode(config)
        manifest['config'] = descriptor(config_data, CONFIG)
        manifest_data = encode(manifest)
        md = descriptor(manifest_data, MANIFEST)
        md['platform'] = {'architecture': 'amd64', 'os': 'linux'}
        md['annotations'] = {'org.opencontainers.image.ref.name': target + ':' + revision}
        index_data = encode(dict(schemaVersion=2, mediaType=INDEX, manifests=[md]))
        written = set()
        output = destination.open('xb')
        try:
            with output, tarfile.open(fileobj=output, mode='w') as out:
                def add(name, data):
                    if name in written:
                        raise ValueError('duplicate output member')
                    written.add(name)
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    info.mode = 0o644
                    out.addfile(info, io.BytesIO(data))
                add('oci-layout', encode({'imageLayoutVersion': '1.0.0'}))
                add('index.json', index_data)
                add(blob_name(manifest['config']), config_data)
                add(blob_name(md), manifest_data)
                for layer in original_layers:
                    if layer.get('mediaType') not in {'application/vnd.oci.image.layer.v1.tar', 'application/vnd.oci.image.layer.v1.tar+gzip', 'application/vnd.oci.image.layer.v1.tar+zstd'} or layer.get('urls'):
                        raise ValueError('unsupported or external layer')
                    name = blob_name(layer)
                    member = by_name[name]
                    if not member.isfile() or member.size != layer['size']:
                        raise ValueError('invalid layer member')
                    h = hashlib.sha256()
                    with archive.extractfile(member) as stream:
                        while block := stream.read(1024 * 1024):
                            h.update(block)
                    if 'sha256:' + h.hexdigest() != layer['digest']:
                        raise ValueError('layer digest mismatch')
                    if name not in written:
                        info = tarfile.TarInfo(name)
                        info.size = member.size
                        info.mode = 0o644
                        with archive.extractfile(member) as stream:
                            out.addfile(info, stream)
                        written.add(name)
            destination.chmod(0o600)
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
    return dict(source=SOURCE, revision=revision, target=target,
                manifest=md['digest'], index='sha256:' + hashlib.sha256(index_data).hexdigest(),
                layers_unchanged=True, layers=original_layers,
                claims={'publication': False, 'runtime_acceptance': False})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--target', required=True, choices=['kernel', 'drbd-pkg'])
    args = parser.parse_args()
    print(json.dumps(finalize(args.source, args.destination, args.revision, args.target), indent=2))


if __name__ == '__main__':
    main()
