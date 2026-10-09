#!/usr/bin/env python3
"""Validate generated GLB structure and local PBR references. Not Khronos Validator."""
from __future__ import annotations
import argparse, hashlib, json, math, struct
from pathlib import Path
import numpy as np

COMP = {5120: np.dtype('i1'), 5121: np.dtype('u1'), 5122: np.dtype('<i2'),
        5123: np.dtype('<u2'), 5125: np.dtype('<u4'), 5126: np.dtype('<f4')}
DIMS = {'SCALAR':1, 'VEC2':2, 'VEC3':3, 'VEC4':4, 'MAT4':16}

def check(root: Path) -> dict:
    root = root.resolve()
    rows = []
    manifest = json.loads((root/'SHA256SUMS.json').read_text())
    for name, digest in manifest.items():
        p = (root/name).resolve()
        assert p.is_relative_to(root), f'unsafe manifest: {name}'
        assert hashlib.sha256(p.read_bytes()).hexdigest() == digest, f'hash mismatch: {name}'
    catalog = json.loads((root/'catalog.json').read_text())
    assert [r['id'] for r in catalog] == [f'A{i:02}' for i in range(1,41)]
    for lod in (0, 1):
        for asset in catalog:
            p = root/f'models/lod{lod}/{asset["id"]}.glb'
            data = p.read_bytes()
            assert struct.unpack_from('<III', data) == (0x46546C67, 2, len(data)), p
            size, typ = struct.unpack_from('<II', data, 12)
            assert typ == 0x4E4F534A
            doc = json.loads(data[20:20+size])
            off = 20+size
            bsize, btyp = struct.unpack_from('<II', data, off)
            assert btyp == 0x004E4942 and off+8+bsize == len(data)
            raw = memoryview(data)[off+8:]
            assert len(doc['buffers']) == 1 and doc['buffers'][0]['byteLength'] <= len(raw)
            for v in doc['bufferViews']:
                assert v.get('buffer',0) == 0
                assert v.get('byteOffset',0)+v['byteLength'] <= doc['buffers'][0]['byteLength']
            def array(idx):
                a = doc['accessors'][idx]
                v = doc['bufferViews'][a['bufferView']]
                dtype, dim = COMP[a['componentType']], DIMS[a['type']]
                stride = v.get('byteStride', dtype.itemsize*dim)
                start = v.get('byteOffset',0)+a.get('byteOffset',0)
                assert a['count'] > 0
                assert a.get('byteOffset',0)+(a['count']-1)*stride+dtype.itemsize*dim <= v['byteLength']
                out = np.ndarray((a['count'],dim), dtype=dtype, buffer=raw,
                                 offset=start, strides=(stride,dtype.itemsize))
                assert np.isfinite(out).all()
                return out
            for idx in range(len(doc['accessors'])):
                array(idx)
            triangles = 0
            for mesh in doc['meshes']:
                for prim in mesh['primitives']:
                    pos = array(prim['attributes']['POSITION'])
                    if 'NORMAL' in prim['attributes']:
                        normals=array(prim['attributes']['NORMAL'])
                        assert np.allclose(np.linalg.norm(normals,axis=1),1,atol=.015)
                    ix=array(prim['indices']).ravel()
                    assert len(ix)%3 == 0 and ix.max() < len(pos)
                    tris=pos[ix.reshape(-1,3)]
                    assert (np.linalg.norm(np.cross(tris[:,1]-tris[:,0],tris[:,2]-tris[:,0]),axis=1)>1e-13).all()
                    triangles += len(ix)//3
            for image in doc.get('images',[]):
                assert 'uri' in image
                ip=(p.parent/image['uri']).resolve()
                assert ip.is_relative_to(root) and ip.is_file(), (p,image)
            for clip in doc.get('animations',[]):
                for ch in clip['channels']:
                    assert 0 <= ch['target']['node'] < len(doc['nodes'])
                for s in clip['samplers']:
                    times=array(s['input']).ravel()
                    assert np.all(np.diff(times)>0)
            rows.append({'id':asset['id'],'lod':lod,'triangles':triangles,
                         'clips':[c['name'] for c in doc.get('animations',[])]})
    return {'ok':True,'validator':'project-specific structure/geometry/reference checker; not Khronos Validator',
            'files':len(rows),'hashed_files':len(manifest),'assets':rows}

if __name__ == '__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1]/'viz/assets/atlas')
    ap.add_argument('--report',type=Path)
    args=ap.parse_args();res=check(args.root)
    if args.report:
        args.report.parent.mkdir(parents=True,exist_ok=True);args.report.write_text(json.dumps(res,ensure_ascii=False,indent=2)+'\n')
    print(f'PASS: {res["files"]} GLBs, {res["hashed_files"]} hashes, geometry and PBR references')
