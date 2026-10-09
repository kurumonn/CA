#!/usr/bin/env python3
"""Build all 40 original Atlas assets, with a restrained hero-detail pass.

Dependencies: numpy, scipy, Pillow. No network, CA state, certificates or keys.
Default output: viz/assets/atlas/. Geometry uses metres, +Y up, +Z front.
The output is an art-production iteration, not a claim of AAA acceptance.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import shutil
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('atlas_base', REPO / 'tools/atlas/base_assets.py')
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


def detail_pass(assets, level):
    lookup = {ident: node for ident, _, _, node in assets}
    # Root vault: hinge mounting plates and visible fasteners, no real security claim.
    n = lookup['A09']
    for y in (.45, 1.35, 2.35):
        b.box(n, (-1.38, y, .86), (.20, .25, .11), 2, .018)
        b.screws(n, [-1.43, -1.33], [y-.08, y+.08], .923)
    # Signing console: panel breaks, recessed fasteners, control bezel and E-stop.
    n = lookup['A12']
    for x in (-1.12, 1.12):
        b.box(n, (x, .70, .766), (.012, 1.10, .012), 5, .002)
        b.screws(n, [x], [.22, 1.19], .788)
    b.box(n, (.82, 1.51, .49), (.49, .06, .33), 1, .02)
    b.cyl(n, (.92, 1.555, .48), .068, .035, 3, seg=32 if level==0 else 16)
    b.cyl(n, (.92, 1.58, .48), .049, .029, 8, seg=32 if level==0 else 16)
    for i in range(3):
        b.cyl(n, (.66 + i*.072, 1.557, .48), .018, .028, 12 if i==0 else 5, seg=16)
    # Rack: mounting rails and captive screw seats.
    n = lookup['A16']
    for x in (-.49, .49):
        b.box(n, (x, 1.20, .56), (.035, 1.93, .025), 2, .005)
        for i in range(12 if level==0 else 6):
            b.cyl(n, (x, .30 + i*(1.72/(11 if level==0 else 5)), .583), .015, .012, 5,
                  b.rot('x', b.math.pi/2), seg=12)
    # Trust drawer: actual tray and dividers rather than only a moving front plate.
    dr = lookup['A17'].children[0]
    b.box(dr, (0, .15, .02), (1.34, .03, .82), 2, .009)
    for x in (-.665, .665):
        b.box(dr, (x, .26, .02), (.026, .23, .80), 2, .009)
    b.box(dr, (0, .26, -.37), (1.31, .23, .026), 2, .009)
    for x in (-.21, .21):
        b.box(dr, (x, .215, .02), (.018, .12, .73), 5, .005)
    # Guide robot: service panel and paired exposed attachment screws.
    n = lookup['A37']
    b.box(n, (0, .87, -.29), (.30, .25, .04), 1, .04)
    for x in (-.09, .09):
        b.cyl(n, (x, .89, -.321), .017, .012, 2, b.rot('x', b.math.pi/2), seg=12)
    return assets


def generate(destination: Path):
    b.ROOT = destination.resolve()
    for d in ('assets/models/lod0', 'assets/models/lod1', 'assets/textures/4k', 'assets/textures/2k'):
        (b.ROOT / d).mkdir(parents=True, exist_ok=True)
    b.texture_atlas()
    catalog = {}
    for level in (0, 1):
        for ident, title, category, node in detail_pass(b.make_assets(level), level):
            g = b.GLB(level)
            g.doc['asset']['generator'] = 'CA Atlas R4 hero-detail builder / symbolic learning assets'
            g.materials[0]['normalTexture']['scale'] = .28
            g.materials[1]['pbrMetallicRoughness']['roughnessFactor'] = .09
            g.node(node, top=True)
            b.add_local_clips(g, node)
            # GLB image URLs are relative to models/lod*/ after output relocation.
            info = g.save(b.ROOT / f'assets/models/lod{level}/{ident}.glb')
            lo, hi = b.asset_bounds(node)
            entry = catalog.setdefault(ident, {'id': ident, 'name': title, 'category': category,
                'bounds': [lo, hi], 'dimensions': [round(hi[i]-lo[i],4) for i in range(3)]})
            entry[f'lod{level}'] = info
    # Base writer's path convention matches ../../textures/, so relocate the entire tree.
    for name in ('models', 'textures'):
        dst = b.ROOT / name
        (b.ROOT / 'assets' / name).rename(dst)
    (b.ROOT/'assets').rmdir()
    (b.ROOT/'textures/4k/COMPLETE').unlink(missing_ok=True)
    (b.ROOT/'catalog.json').write_text(json.dumps(list(catalog.values()), ensure_ascii=False, indent=2)+'\n')
    hashes = {str(p.relative_to(b.ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in sorted(b.ROOT.rglob('*')) if p.is_file() and p.name != 'SHA256SUMS.json'}
    (b.ROOT/'SHA256SUMS.json').write_text(json.dumps(hashes, indent=2)+'\n')
    print(f'Built {len(catalog)} assets x 2 LODs; shared 2K/4K PBR atlases.')


def build(destination: Path):
    """Generate in a sibling staging directory. Never erase an unknown destination."""
    destination = destination.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and not (destination/'catalog.json').is_file():
        raise RuntimeError('Output exists without Atlas catalog.json; choose a new output directory')
    staging = Path(tempfile.mkdtemp(prefix='.atlas-build-', dir=destination.parent))
    previous = destination.with_name(destination.name+'.previous')
    try:
        if previous.exists():
            raise RuntimeError(f'Previous build preserved at {previous}; inspect before retrying')
        generate(staging)
        from check_atlas import check
        check(staging)
        if destination.exists():
            destination.rename(previous)
        try:
            staging.rename(destination)
        except BaseException:
            if previous.exists():
                previous.rename(destination)
            raise
        if previous.exists():
            shutil.rmtree(previous)
    finally:
        if staging.exists():
            shutil.rmtree(staging)


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', type=Path, default=REPO/'viz/assets/atlas')
    args = ap.parse_args()
    build(args.out)
