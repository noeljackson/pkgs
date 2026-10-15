#!/usr/bin/env python3
import importlib.util
import sys
sys.dont_write_bytecode = True
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
spec=importlib.util.spec_from_file_location('finalizer',Path(__file__).with_name('finalize-package-oci.py'))
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
REVISION='a'*40
class FinalizeTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.root=Path(self.temp.name);self.source=self.root/'source.tar';self.dest=self.root/'result.tar'
 def fixture(self,*,corrupt=False,duplicate=False,platform=None,config_platform=None,many=False):
  layer=b'synthetic immutable filesystem layer';ld=f.descriptor(layer,'application/vnd.oci.image.layer.v1.tar')
  config={'architecture':'amd64','os':'linux','rootfs':{'type':'layers','diff_ids':[ld['digest']]},'config':{'Labels':{'existing':'preserved'}}}
  config.update(config_platform or {});cd=f.encode(config);c=f.descriptor(cd,f.CONFIG)
  manifest={'schemaVersion':2,'mediaType':f.MANIFEST,'config':c,'layers':[ld]};md=f.encode(manifest);m=f.descriptor(md,f.MANIFEST);m['platform']=platform or {'architecture':'amd64','os':'linux'}
  entries={'oci-layout':f.encode({'imageLayoutVersion':'1.0.0'}),'index.json':f.encode({'schemaVersion':2,'mediaType':f.INDEX,'manifests':[m,m] if many else [m]}),f.blob_name(c):cd,f.blob_name(m):md,f.blob_name(ld):b'corrupted' if corrupt else layer}
  with tarfile.open(self.source,'w') as archive:
   for name,data in list(entries.items())+([('index.json',entries['index.json'])] if duplicate else []):
    info=tarfile.TarInfo(name);info.size=len(data);archive.addfile(info,io.BytesIO(data))
  return layer,ld,config
 def run_finalize(self,revision=REVISION,target='kernel'):
  return f.finalize(self.source,self.dest,revision,target)
 def test_labels_and_every_payload_byte_preserved(self):
  layer,ld,old=self.fixture();r=self.run_finalize();self.assertTrue(r['layers_unchanged']);self.assertEqual(r['layers'],[ld])
  with tarfile.open(self.dest) as a:
   read=lambda name:a.extractfile(name).read()
   index=json.loads(read('index.json'));manifest=json.loads(read(f.blob_name(index['manifests'][0])));config=json.loads(read(f.blob_name(manifest['config'])))
   self.assertEqual(read(f.blob_name(ld)),layer);self.assertEqual(config['rootfs'],old['rootfs'])
   self.assertEqual(config['config']['Labels'],{'existing':'preserved','org.opencontainers.image.source':f.SOURCE,'org.opencontainers.image.revision':REVISION,'org.opencontainers.image.title':'kernel'})
   self.assertEqual(f.descriptor(read(f.blob_name(manifest['config'])),f.CONFIG),manifest['config'])
   self.assertEqual(f.descriptor(read(f.blob_name(index['manifests'][0])),f.MANIFEST)['digest'],r['manifest'])
  self.assertEqual(self.dest.stat().st_mode&0o777,0o600)
 def test_existing_destination_is_preserved(self):
  self.fixture();self.dest.write_text('preserve')
  with self.assertRaises(ValueError):self.run_finalize()
  self.assertEqual(self.dest.read_text(),'preserve')
 def test_no_private_intermediate_target(self):
  self.fixture()
  with self.assertRaises(ValueError):self.run_finalize(target='kernel-build')
  self.assertFalse(self.dest.exists())
 def test_full_revision_required(self):
  self.fixture()
  for rev in ['', 'a'*8, 'a'*39+'G']:
   with self.subTest(rev=rev),self.assertRaises(ValueError):self.run_finalize(revision=rev)
  self.assertFalse(self.dest.exists())
 def test_corrupt_layer_leaves_no_output(self):
  self.fixture(corrupt=True)
  with self.assertRaises(ValueError):self.run_finalize()
  self.assertFalse(self.dest.exists())
 def test_duplicate_member_rejected(self):
  self.fixture(duplicate=True)
  with self.assertRaises(ValueError):self.run_finalize()
  self.assertFalse(self.dest.exists())
 def test_wrong_or_multiple_platforms_rejected(self):
  for kwargs in [dict(platform={'architecture':'arm64','os':'linux'}),dict(config_platform={'architecture':'arm64'}),dict(many=True)]:
   with self.subTest(kwargs=kwargs):
    self.fixture(**kwargs)
    with self.assertRaises(ValueError):self.run_finalize()
    self.assertFalse(self.dest.exists())
if __name__=='__main__':unittest.main()
