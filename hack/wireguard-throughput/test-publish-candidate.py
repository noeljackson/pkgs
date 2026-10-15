#!/usr/bin/env python3
"""Offline publication-boundary regressions; no credentials or network."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
sys.dont_write_bytecode = True
import tarfile
import tempfile
import unittest


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


p = module('publisher', 'publish-candidate.py')
fixtures = module('finalizer_fixtures', 'test-finalize-package-oci.py')
REV = 'a' * 40
DIGEST = 'sha256:' + 'b' * 64


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fixture = fixtures.FinalizeTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def package(self, target='kernel'):
        self.fixture.fixture()
        receipt = self.fixture.run_finalize(revision=REV, target=target)
        return self.fixture.dest, receipt

    def test_qualified_layout_and_payload_bytes_are_preserved(self):
        archive, receipt = self.package()
        layout = self.root / 'layout'
        p.unpack(archive, layout, p.sha(archive))
        p.inspect_layout(layout, 'kernel', REV, receipt['manifest'])
        with tarfile.open(archive) as source:
            for member in source:
                self.assertEqual((layout / member.name).read_bytes(), source.extractfile(member).read())

    def test_archive_checksum_failure_precedes_extraction(self):
        archive, _ = self.package()
        layout = self.root / 'layout'
        with self.assertRaisesRegex(ValueError, 'archive checksum'):
            p.unpack(archive, layout, '0' * 64)
        self.assertFalse(layout.exists())

    def test_source_target_and_manifest_cannot_be_substituted(self):
        archive, receipt = self.package()
        layout = self.root / 'layout'
        p.unpack(archive, layout, p.sha(archive))
        for target, revision, digest in [('drbd-pkg', REV, receipt['manifest']),
                                         ('kernel', 'b' * 40, receipt['manifest']),
                                         ('kernel', REV, DIGEST)]:
            with self.subTest(target=target, revision=revision), self.assertRaises(ValueError):
                p.inspect_layout(layout, target, revision, digest)

    def test_corrupt_blob_is_rejected(self):
        archive = self.root / 'corrupt.tar'
        with tarfile.open(archive, 'w') as out:
            member = tarfile.TarInfo('blobs/sha256/' + '0' * 64)
            member.size = 4
            out.addfile(member, io.BytesIO(b'bad!'))
        with self.assertRaisesRegex(ValueError, 'blob digest'):
            p.unpack(archive, self.root / 'layout', p.sha(archive))
        self.assertFalse((self.root / 'layout').exists())

    def test_paths_links_and_duplicate_members_cannot_escape(self):
        for index, kind in enumerate(('escape', 'link', 'duplicate')):
            archive = self.root / (kind + '.tar')
            with tarfile.open(archive, 'w') as out:
                member = tarfile.TarInfo('../escape' if kind == 'escape' else 'index.json')
                if kind == 'link':
                    member.type = tarfile.SYMTYPE
                    member.linkname = '../escape'
                    out.addfile(member)
                else:
                    member.size = 2
                    out.addfile(member, io.BytesIO(b'{}'))
                    if kind == 'duplicate':
                        out.addfile(member, io.BytesIO(b'{}'))
            layout = self.root / ('layout-' + str(index))
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                p.unpack(archive, layout, p.sha(archive))
            self.assertFalse(layout.exists())
            self.assertFalse((self.root / 'escape').exists())

    def test_existing_layout_is_untouched(self):
        archive, _ = self.package()
        layout = self.root / 'layout'
        layout.mkdir()
        (layout / 'keep').write_text('owned elsewhere')
        with self.assertRaises(ValueError):
            p.unpack(archive, layout, p.sha(archive))
        self.assertEqual((layout / 'keep').read_text(), 'owned elsewhere')

    def test_publication_requires_exact_owned_push_and_clean_source(self):
        env = dict(GITHUB_ACTIONS='true', GITHUB_EVENT_NAME='push',
                   GITHUB_REPOSITORY='noeljackson/pkgs', GITHUB_REF='refs/heads/ams-fra-throughput',
                   GITHUB_SHA=REV)
        p.require_context(env, REV, True, True)
        for key in env:
            changed = dict(env, **{key: 'foreign'})
            with self.subTest(key=key), self.assertRaises(ValueError):
                p.require_context(changed, REV, True, True)
        for clean, ancestor in ((False, True), (True, False)):
            with self.assertRaises(ValueError):
                p.require_context(env, REV, clean, ancestor)

    def test_destinations_are_closed_and_immutable(self):
        for target in p.TARGETS:
            self.assertEqual(p.destination(target, DIGEST), 'ghcr.io/noeljackson/' + target + '@' + DIGEST)
        for target, digest in [('kernel-build', DIGEST), ('../kernel', DIGEST), ('kernel', 'latest')]:
            with self.assertRaises(ValueError):
                p.destination(target, digest)

    def test_only_complete_checked_in_pair_is_admitted(self):
        lock = dict(schema='wireguard.package-publication/v1', source_revision=REV, release_id=1,
                    packages={target: dict(asset_id=i + 1, archive_sha256='c' * 64, manifest=DIGEST)
                              for i, target in enumerate(p.TARGETS)})
        p.validate_lock(lock)
        changes = [dict(source_revision=REV[:8]), dict(release_id=True), dict(destination='foreign')]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                p.validate_lock(dict(lock, **change))
        changed = copy.deepcopy(lock)
        del changed['packages']['drbd-pkg']
        with self.assertRaises(ValueError):
            p.validate_lock(changed)


if __name__ == '__main__':
    unittest.main()
