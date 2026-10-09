#!/usr/bin/env python3
"""Deterministic, procedural hard-surface PKI exhibition assets.
No keys, certificates or cryptographic operations are performed here.
Requires numpy, scipy and Pillow. Units: metres, +Y up, +Z front.
"""
from __future__ import annotations
from pathlib import Path
import json, math, struct, hashlib, csv
from collections import defaultdict
import numpy as np
from PIL import Image
from scipy.ndimage import gaussian_filter

ROOT=Path(__file__).resolve().parents[1]
TAU=2*math.pi
LEVEL=0
SEG=48
BEV=4
TEX_NAMES=['basecolor.jpg','normal.png','orm.png']
# These are artistic colors, not CA status encodings.
PALETTE=[(221,224,215),(26,46,62),(164,178,187),(179,133,63),(170,180,176),(24,30,34),(100,62,36),(242,237,222),(167,52,43),(43,111,149),(20,29,37),(199,207,209),(117,172,149),(211,158,66),(112,96,141),(9,16,21)]
ROUGH=[.33,.44,.27,.25,.76,.81,.47,.8,.42,.32,.12,.2,.45,.46,.45,.65]
METAL=[0,.7,1,1,0,0,0,0,.25,.55,.15,1,0,.1,.15,0]


def texture_atlas():
    target=ROOT/'assets/textures/4k'
    if (target/'COMPLETE').exists(): return
    n=1024; rng=np.random.default_rng(42067)
    base=np.zeros((n*4,n*4,3),np.uint8);norm=np.zeros_like(base);orm=np.zeros_like(base)
    for k,col in enumerate(PALETTE):
        rnd=rng.normal(0,1,(n,n)).astype(np.float32)
        low=gaussian_filter(rnd,21,mode='wrap'); low/=max(float(low.std()),1e-5)
        fine=gaussian_filter(rnd,.65,mode='wrap'); fine/=max(float(fine.std()),1e-5)
        y,x=np.mgrid[:n,:n].astype(np.float32); x/=n;y/=n
        h=.2*fine+.3*low;var=1.4*fine+1.7*low
        if k in (2,3,11):
            streak=gaussian_filter(rnd,(.65,30),mode='wrap');streak/=max(float(streak.std()),1e-5)
            h=.35*streak+.08*fine;var=2.3*streak+.4*low
        if k==6:
            w=gaussian_filter(rnd,(40,5),mode='wrap');w/=max(float(w.std()),1e-5)
            grain=np.sin(TAU*(48*x+1.6*np.sin(TAU*y)+.22*w))
            h=.16*grain+.06*fine;var=9*grain+3*w
        if k==4: h=.18*fine+.32*low;var=2.8*fine+4*low
        rgb=np.clip(np.array(col)[None,None,:]+var[:,:,None],0,255).astype(np.uint8)
        dx=(np.roll(h,-1,1)-np.roll(h,1,1))*.10
        dy=(np.roll(h,-1,0)-np.roll(h,1,0))*.10
        v=np.stack([-dx,dy,np.ones_like(dx)],axis=2);v/=np.linalg.norm(v,axis=2,keepdims=True)
        nm=np.clip((v*.5+.5)*255,0,255).astype(np.uint8)
        rm=np.empty_like(rgb);rm[:,:,0]=255
        rm[:,:,1]=np.clip(255*(ROUGH[k]+.018*low+.008*fine),5,252)
        rm[:,:,2]=int(255*METAL[k])
        a,b=divmod(k,4);sl=np.s_[a*n:(a+1)*n,b*n:(b+1)*n]
        base[sl]=rgb;norm[sl]=nm;orm[sl]=rm
    Image.fromarray(base).save(target/'basecolor.jpg',quality=94,subsampling=0)
    norm=(np.round(norm.astype(float)/3)*3).clip(0,255).astype(np.uint8)
    Image.fromarray(norm).save(target/'normal.png',compress_level=2)
    Image.fromarray(orm).save(target/'orm.png',compress_level=2)
    for name in TEX_NAMES:
        im=Image.open(target/name).resize((2048,2048),Image.Resampling.LANCZOS)
        kw={'quality':92,'subsampling':0} if name.endswith('.jpg') else {'compress_level':2}
        im.save(ROOT/'assets/textures/2k'/name,**kw)
    (target/'COMPLETE').write_text('Texture generation complete; no photographic inputs.')


def rot(axis,angle):
    c,s=math.cos(angle),math.sin(angle)
    if axis=='x': return np.array([[1,0,0],[0,c,-s],[0,s,c]],float)
    if axis=='y': return np.array([[c,0,s],[0,1,0],[-s,0,c]],float)
    return np.array([[c,-s,0],[s,c,0],[0,0,1]],float)

def quat(axis,angle):
    q=[0.,0.,0.,math.cos(angle/2)];q['xyz'.index(axis)]=math.sin(angle/2);return q

def uv_tile(uv,k):
    # glTF V follows image row ordering. Insets prevent neighboring atlas bleed.
    uv=np.asarray(uv,float);a,b=divmod(k,4)
    return (uv*.968 + np.array([b,a])+.016)/4

class Node:
    def __init__(self,name,xyz=(0,0,0),rotation=None,extras=None):
        self.name=name; self.xyz=list(xyz);self.rotation=rotation;self.parts=defaultdict(list);self.children=[];self.extras=extras or {}
    def child(self,name,xyz=(0,0,0),rotation=None,extras=None):
        n=Node(name,xyz,rotation,extras);self.children.append(n);return n
    def add(self,v,f,n,uv,tile=0,mat='atlas',p=(0,0,0),R=None):
        v=np.array(v,float);n=np.array(n,float)
        if R is not None: v=v@R.T;n=n@R.T
        v+=np.array(p)
        uv=uv_tile(uv,tile) if mat=='atlas' else np.asarray(uv)
        self.parts[mat].append((v.astype('f4'),np.asarray(f,'u4'),n.astype('f4'),uv.astype('f4')))
    def geometry(self):
        out={}
        for mat,parts in self.parts.items():
            off=0;vv=[];ff=[];nn=[];uu=[]
            for v,f,n,u in parts:
                vv.append(v);ff.append(f+off);nn.append(n);uu.append(u);off+=len(v)
            out[mat]=(np.concatenate(vv),np.concatenate(ff),np.concatenate(nn),np.concatenate(uu))
        return out


def box(o,p,d,tile=0,r=.035,mat='atlas',R=None):
    d=np.asarray(d,float);h=d/2;r=min(r,float(min(h))*.8)
    ins=h-r
    axes=[]
    for hh,ii in zip(h,ins):
        xs=[-hh,-ii,ii,hh]
        if r>0:
            xs += [float(ii+r*math.sin(t)) for t in np.linspace(0,math.pi/2,BEV+1)]
            xs += [float(-ii-r*math.sin(t)) for t in np.linspace(0,math.pi/2,BEV+1)]
        axes.append(np.array(sorted(set(round(t,8) for t in xs))))
    V=[];N=[];U=[];F=[]
    for a in range(3):
        b=(a+1)%3;c=(a+2)%3
        for sign in [-1,1]:
            base=len(V);xb,yc=axes[b],axes[c]
            for yy in yc:
                for xx in xb:
                    pt=np.zeros(3);pt[a]=sign*h[a];pt[b]=xx;pt[c]=yy
                    cl=np.clip(pt,-ins,ins);n=pt-cl;ln=np.linalg.norm(n)
                    n=n/ln if ln>1e-9 else np.eye(3)[a]*sign
                    v=cl+n*r
                    V.append(v);N.append(n);U.append([xx/d[b]+.5,.5-yy/d[c]])
            for j in range(len(yc)-1):
                for i in range(len(xb)-1):
                    aa=base+j*len(xb)+i;bb=aa+1;cc=aa+len(xb);dd=cc+1
                    F.extend([(aa,bb,cc),(bb,dd,cc)] if sign==1 else [(aa,cc,bb),(bb,cc,dd)])
    o.add(V,F,N,U,tile,mat,p,R)


def lathe(o,p,profile,tile=2,mat='atlas',R=None,segments=None):
    seg=segments or SEG;P=np.array(profile,float);V=[];N=[];U=[];F=[]
    # Each profile edge has its own normals; intentional machining creases remain sharp.
    heights=P[:,1];lo=float(min(heights));hh=max(float(max(heights)-lo),1e-6)
    for a,b in zip(P[:-1],P[1:]):
        if np.linalg.norm(a-b)<1e-9: continue
        dr,dy=b-a;nn=np.array([dy,-dr]);nn/=np.linalg.norm(nn)
        base=len(V)
        for rr,yy in [a,b]:
            for j in range(seg+1):
                th=TAU*j/seg;c,s=math.cos(th),math.sin(th)
                V.append([rr*c,yy,rr*s]);N.append([nn[0]*c,nn[1],nn[0]*s]);U.append([j/seg,(yy-lo)/hh])
        for j in range(seg):
            aa=base+j;bb=aa+1;cc=aa+seg+1;dd=cc+1
            # reversed with respect to du x dv: radial outward.
            if a[0]>1e-8: F.append((aa,cc,bb))
            if b[0]>1e-8: F.append((bb,cc,dd))
    o.add(V,F,N,U,tile,mat,p,R)

def cyl(o,p,r,h,tile=2,R=None,mat='atlas',seg=None):
    be=min(.012,r*.14,h*.16)
    pro=[(0,-h/2),(r-be,-h/2),(r,-h/2+be),(r,h/2-be),(r-be,h/2),(0,h/2)]
    lathe(o,p,pro,tile,mat,R,seg)

def torus(o,p,major,minor,tile=2,R=None,mat='atlas',seg=None):
    nu=seg or SEG;nv=max(8,SEG//4);V=[];N=[];U=[];F=[]
    for j in range(nv+1):
        v=TAU*j/nv
        for i in range(nu+1):
            u=TAU*i/nu;c,s=math.cos(u),math.sin(u);cv,sv=math.cos(v),math.sin(v)
            V.append([(major+minor*cv)*c,(major+minor*cv)*s,minor*sv]);N.append([cv*c,cv*s,sv]);U.append([i/nu,j/nv])
    for j in range(nv):
        for i in range(nu):
            a=j*(nu+1)+i;b=a+1;c=a+nu+1;dd=c+1;F.extend([(a,b,c),(b,dd,c)])
    o.add(V,F,N,U,tile,mat,p,R)

def sphere(o,p,r,tile=0,scale=(1,1,1),mat='atlas'):
    nu=SEG;nv=max(8,SEG//2);V=[];N=[];U=[];F=[];sc=np.array(scale)
    for j in range(nv+1):
        phi=math.pi*j/nv
        for i in range(nu+1):
            th=TAU*i/nu;n=np.array([math.sin(phi)*math.cos(th),math.cos(phi),math.sin(phi)*math.sin(th)])
            V.append(n*r*sc);no=n/sc;no/=np.linalg.norm(no);N.append(no);U.append([i/nu,j/nv])
    for j in range(nv):
        for i in range(nu):
            a=j*(nu+1)+i;b=a+1;c=a+nu+1;dd=c+1
            if j>0:F.append((a,b,c))
            if j<nv-1:F.append((b,dd,c))
    o.add(V,F,N,U,tile,mat,p)

def rod(o,a,b,r,tile=2,mat='atlas'):
    a=np.array(a);b=np.array(b);dv=b-a;h=np.linalg.norm(dv);y=dv/h
    helper=np.array([0,0,1]) if abs(y[2])<.9 else np.array([1,0,0])
    x=np.cross(y,helper);x/=np.linalg.norm(x);z=np.cross(x,y)
    cyl(o,(a+b)/2,r,h,tile,np.column_stack([x,y,z]),mat)

def bolt(o,p,size=.025):
    if LEVEL: return
    cyl(o,p,size,.015,11,rot('x',math.pi/2),seg=12)
    box(o,np.array(p)+[0,0,.009],(size*.95,size*.2,.002),15,.001)

def screws(o,xs,ys,z,size=.025):
    for x in xs:
        for y in ys:bolt(o,(x,y,z),size)

def feet(o,x,z):
    for xx in [-x,x]:
        for zz in [-z,z]:cyl(o,(xx,.06,zz),.075,.12,5)

def card_lines(o,z,w=1.05,ystart=1.35,n=5):
    for i in range(n):
        box(o,(-.08,ystart-i*.115,z),(w*(1-.11*(i%3)),.018,.008),2,.003)

def grille(o,p,w,h,rows=14):
    # Recessed black bed + individually beveled metal louvers.
    x,y,z=p;box(o,p,(w,h,.025),15,.025)
    rows=rows if not LEVEL else max(4,rows//2)
    for i in range(rows):box(o,(x,y-h/2+(i+.5)*h/rows,z+.02),(w-.045,.012,.015),2,.003)

ASSETS=[]
def asset(id,title,category):
    n=Node(id,extras={'asset_id':id,'title_ja':title,'category':category,'units':'metre','symbolic_only':True})
    ASSETS.append((id,title,category,n));return n

def make_assets(level):
    global ASSETS,LEVEL,SEG,BEV
    ASSETS=[];LEVEL=level;SEG=48 if level==0 else 20;BEV=4 if level==0 else 2
    o=asset('A01','展示基壇','architecture');box(o,(0,-.23,0),(28,.46,20),1,.2);box(o,(0,.005,0),(27.7,.04,19.7),4,.1)
    o=asset('A02','床タイル・見切り','architecture');box(o,(0,.06,0),(1.98,.12,1.98),0,.014)
    o=asset('A03','壁パネル・吸気スリット','architecture');box(o,(0,1.65,0),(2,3.3,.18),1,.045);box(o,(0,1.73,.12),(1.88,2.94,.06),0,.025);grille(o,(0,.34,.16),1.7,.18,4);box(o,(0,3.12,.18),(1.72,.018,.02),0,.004,'light_white');screws(o,[-.86,.86],[.65,2.88],.17)
    o=asset('A04','ガラス間仕切り','architecture');box(o,(0,1.35,0),(1.86,2.5,.025),0,.002,'glass')
    for x in [-.97,.97]:box(o,(x,1.4,0),(.065,2.8,.095),2,.016)
    for y in [.1,2.74]:box(o,(0,y,0),(2,.055,.095),2,.012)
    o=asset('A05','区画入口フレーム','architecture')
    for x in [-1.45,1.45]:box(o,(x,1.6,0),(.18,3.2,.3),1,.055);box(o,(x*.97,1.6,.17),(.035,2.8,.03),3,.006)
    box(o,(0,3.15,0),(3.1,.26,.3),1,.06)
    o=asset('A06','線状照明','architecture');box(o,(0,.08,0),(2.4,.16,.38),1,.04);box(o,(0,-.005,0),(2.15,.025,.27),0,.02,'light_white')
    o=asset('A07','境界ポール','architecture');cyl(o,(0,.035,0),.16,.07,2);cyl(o,(0,.55,0),.035,1.04,2);cyl(o,(0,1.08,0),.055,.075,3)
    o=asset('A08','展示台座','architecture');box(o,(0,.25,0),(1.5,.5,1.5),1,.08);box(o,(0,.515,0),(1.44,.05,1.44),6,.025)
    o=asset('A09','ルートCA金庫・本体','root');box(o,(0,1.42,0),(2.9,2.84,1.5),1,.12)
    box(o,(0,1.44,.77),(2.66,2.62,.13),2,.11);box(o,(0,1.44,.85),(2.43,2.38,.06),15,.11)
    for x in [-1.2,1.2]:box(o,(x,1.44,.92),(.10,2.18,.22),3,.025)
    for y in [.34,2.54]:box(o,(0,y,.92),(2.42,.10,.22),3,.025)
    grille(o,(0,2.65,.94),1.3,.12,3);screws(o,[-1.31,1.31],[.28,1.45,2.6],.865,.045)
    for x in [-1.5,1.5]:box(o,(x,1.48,-.22),(.14,2.55,1.03),2,.05)
    # Door origin is at its left hinge axis. Independent asset A10 below.
    o=asset('A10','金庫扉・可動ヒンジ','root');hinge=o.child('hinge',(-1.08,0,0),extras={'animated':True})
    box(hinge,(1.08,1.44,0),(2.12,2.11,.19),1,.13);box(hinge,(1.08,1.44,.12),(1.91,1.91,.10),2,.12)
    for y in [.56,2.32]:cyl(hinge,(0,y,-.06),.08,.4,3)
    cyl(hinge,(1.08,1.5,.2),.55,.10,1,rot('x',math.pi/2));torus(hinge,(1.08,1.5,.29),.46,.041,3)
    for i in range(6):
        a=TAU*i/6;rod(hinge,(1.08,1.5,.3),(1.08+.4*math.cos(a),1.5+.4*math.sin(a),.3),.03,3)
    cyl(hinge,(1.08,1.5,.34),.13,.12,11,rot('x',math.pi/2));box(hinge,(1.69,.61,.2),(.31,.27,.045),15,.03)
    for i in range(9):cyl(hinge,(1.59+(i%3)*.10,.52+(i//3)*.085,.232),.018,.01,3,rot('x',math.pi/2),seg=12)
    screws(hinge,[.3,1.86],[.67,2.2],.18,.028)
    o=asset('A11','秘密鍵固定台・保護カバー','root');box(o,(0,.12,0),(1.08,.24,.64),1,.07)
    for x in [-.43,.43]:box(o,(x,.42,0),(.08,.42,.35),3,.025)
    box(o,(0,.50,.26),(1.02,.69,.015),0,.005,'glass');box(o,(0,.85,0),(1.02,.035,.55),2,.009)
    o=asset('A12','中間CA署名コンソール','issuer');feet(o,1.0,.5);box(o,(0,.74,0),(2.5,1.38,1.5),1,.09);box(o,(0,1.46,0),(2.62,.1,1.58),2,.045)
    grille(o,(-.6,.74,.77),.76,.8,16);box(o,(.55,.78,.77),(.76,.93,.04),0,.04);screws(o,[.25,.85],[.4,1.16],.81)
    for x in [-.79,.79]:cyl(o,(x,1.97,-.27),.065,1.03,11)
    box(o,(0,2.48,-.27),(1.91,.21,.62),1,.075);cyl(o,(0,2.35,-.15),.13,.4,2)
    press=o.child('press',(0,0,0),extras={'animated':True});cyl(press,(0,2.1,-.15),.16,.32,3);box(press,(0,1.925,-.15),(.62,.08,.45),3,.02)
    box(o,(0,1.54,-.15),(.81,.06,.65),5,.02);box(o,(.88,1.62,.52),(.48,.09,.35),9,.025)
    o=asset('A13','RA申請受付カウンター','office');box(o,(0,.5,0),(3.2,1,1.45),0,.26);box(o,(0,1.06,0),(3.35,.13,1.58),6,.14);box(o,(0,.48,.74),(2.58,.62,.02),1,.08)
    for x in np.linspace(-1.2,1.2,25 if not LEVEL else 13):box(o,(x,.48,.77),(.022,.57,.034),3,.004)
    o=asset('A14','利用者モニター','office');box(o,(0,.035,0),(.82,.07,.5),2,.06);cyl(o,(0,.36,-.04),.075,.6,2);box(o,(0,.94,-.01),(1.38,.83,.10),1,.05);box(o,(0,.94,.05),(1.28,.73,.018),10,.025)
    for i in range(4):box(o,(-.22,1.12-i*.11,.063),(.63-(i%2)*.18,.023,.006),9,.003,'light_teal')
    cyl(o,(.60,.575,.06),.016,.01,3,rot('x',math.pi/2),seg=12)
    o=asset('A15','キーボード','office');box(o,(0,.028,0),(1.04,.056,.38),1,.03)
    for row in range(4):
        for col in range(14 if not LEVEL else 7):
            n=14 if not LEVEL else 7;box(o,(-.47+col*.94/(n-1),.067,-.135+row*.078),(.053 if not LEVEL else .11,.025,.055),0,.006)
    box(o,(0,.08,.18),(.33,.018,.05),2,.004)
    o=asset('A16','HTTPSサーバーラック','server');feet(o,.43,.36);box(o,(0,1.23,0),(1.14,2.42,.97),1,.065)
    for x in [-.48,.48]:box(o,(x,1.23,.52),(.07,2.23,.08),2,.015)
    for i in range(7):
        y=.3+i*.3;box(o,(0,y,.53),(.83,.24,.10),2,.02);grille(o,(-.08,y,.60),.56,.15,4)
        for yy in [-.055,0,.055]:box(o,(.32,y+yy,.599),(.042,.026,.022),0,.004,'light_teal')
        screws(o,[-.39,.39],[y],.605,.015)
    for x in [-.25,.25]:
        cyl(o,(x,2.2,.57),.14,.08,15,rot('x',math.pi/2));torus(o,(x,2.2,.62),.11,.01,2)
        for k in range(5):
            a=TAU*k/5;rod(o,(x,2.2,.623),(x+.087*math.cos(a),2.2+.087*math.sin(a),.623),.011,2)
    o=asset('A17','利用側の信頼ストア','client');box(o,(0,.78,0),(1.62,1.56,.95),1,.08);box(o,(0,1.59,0),(1.7,.065,1.01),6,.03)
    for i in range(3):
        dr=o.child('drawer_'+str(i),(0,0,0),extras={'animated':i==0});y=.30+i*.44
        box(dr,(0,y,.51),(1.44,.36,.12),0,.04);box(dr,(0,y,.59),(.41,.075,.08),3,.02);box(dr,(-.47,y+.09,.581),(.29,.08,.01),7,.01)
    o=asset('A18','検証ゲート・可動扉','verification')
    for x in [-.8,.8]:
        box(o,(x,1.34,0),(.17,2.68,.37),1,.07);box(o,(x*.90,1.4,.2),(.027,2.36,.015),0,.004,'light_teal')
    box(o,(0,2.67,0),(1.78,.18,.37),2,.06);box(o,(0,.035,0),(1.96,.07,.69),2,.03)
    for side in [-1,1]:
        dr=o.child('shutter_'+('L' if side<0 else 'R'),(0,0,0),extras={'animated':True});box(dr,(side*.36,1.17,0),(.72,1.58,.035),0,.012,'glass');box(dr,(side*.02,1.17,.03),(.018,1.50,.035),3,.004)
    o=asset('A19','検証チェックリスト端末','verification');cyl(o,(0,.05,0),.32,.1,1);cyl(o,(0,.65,0),.065,1.2,2);box(o,(0,1.39,0),(.77,.81,.09),1,.045)
    for i in range(6):
        cyl(o,(-.25,1.65-i*.105,.058),.022,.01,12,rot('x',math.pi/2),seg=12);box(o,(.07,1.65-i*.105,.052),(.40,.022,.012),2,.003)
    o=asset('A20','CRL配布キャビネット','revocation');box(o,(0,1.02,0),(1.78,2.04,1.12),1,.1);box(o,(0,1.1,.575),(1.54,1.55,.065),0,.05)
    for x in [-.38,.38]:
        box(o,(x,1.18,.66),(.55,1.23,.08),2,.04)
        for i in range(7):box(o,(x,1.62-i*.135,.71),(.38,.024,.011),9,.004)
    grille(o,(0,.30,.625),1.24,.15,4);screws(o,[-.75,.75],[.44,1.87],.625)
    o=asset('A21','OCSP比較展示キオスク','revocation');cyl(o,(0,.04,0),.48,.08,1);cyl(o,(0,.65,0),.105,1.2,2);box(o,(0,1.45,0),(1.06,.8,.20),1,.08)
    for i,t in enumerate([12,8,13]):cyl(o,(-.32+i*.32,1.47,.135),.11,.06,t,rot('x',math.pi/2))
    box(o,(0,1.14,.115),(.67,.065,.025),13,.01)
    o=asset('A22','監査記録キャビネット','office');box(o,(0,1.06,0),(1.42,2.12,.74),1,.07)
    for i in range(5):
        y=.24+i*.40;box(o,(0,y,.405),(1.26,.34,.06),6,.03);box(o,(0,y,.46),(.35,.045,.08),3,.014);box(o,(-.42,y+.06,.445),(.21,.08,.01),7,.01)
    o=asset('A23','公開データ搬送ケース','root');box(o,(0,.18,0),(.86,.36,.60),1,.055);box(o,(0,.29,.01),(.86,.035,.6),2,.01)
    for x in [-.3,.3]:box(o,(x,.32,.31),(.10,.12,.025),3,.02)
    for x in [-.39,.39]:
        for z in [-.26,.26]:box(o,(x,.18,z),(.08,.35,.08),5,.022)
    rod(o,(-.15,.385,0),(-.15,.46,0),.016,2);rod(o,(.15,.385,0),(.15,.46,0),.016,2);rod(o,(-.15,.46,0),(.15,.46,0),.016,2)
    o=asset('A24','秘密鍵の象徴モデル','concept');torus(o,(0,1.12,0),.25,.057,3);box(o,(0,.55,0),(.105,.82,.10),3,.02)
    for x,y in [(.105,.20),(.14,.37),(.09,.54)]:box(o,(x,y,0),(.23,.09,.10),3,.014)
    torus(o,(0,1.12,.019),.17,.018,11)
    o=asset('A25','公開鍵の象徴モデル','concept');torus(o,(0,.63,0),.36,.06,9);torus(o,(0,.63,.013),.255,.022,11)
    for y in [.42,.58,.74]:box(o,(0,y,.02),(.32,.039,.056),9,.009)
    for x in [-.43,.43]:box(o,(x,.63,0),(.12,.12,.10),2,.02)
    o=asset('A26','CSR申込フォルダー','concept');box(o,(0,.69,0),(1.10,1.38,.06),9,.055);box(o,(0,.69,.04),(.98,1.25,.015),7,.03);card_lines(o,.055,.72,1.14,6)
    lid=o.child('cover',(-.55,0,.075),extras={'animated':True});box(lid,(.55,.69,0),(1.10,1.38,.035),9,.05);box(lid,(.55,1.14,.026),(.71,.085,.01),2,.01);cyl(lid,(.55,.53,.041),.20,.028,2,rot('x',math.pi/2));torus(lid,(.55,.53,.064),.125,.018,9)
    for id,title,tile,count in [('A27','サーバー証明書カード',9,1),('A28','中間CA証明書カード',2,2),('A29','ルートCA証明書カード',3,3)]:
        o=asset(id,title,'concept');box(o,(0,.88,0),(1.36,1.76,.065),tile,.075);box(o,(0,.90,.042),(1.21,1.59,.025),7,.052);box(o,(0,1.52,.063),(.87,.08,.008),tile,.01);card_lines(o,.064,.95,1.30,6)
        cyl(o,(.35,.30,.08),.155,.035,tile,rot('x',math.pi/2));torus(o,(.35,.30,.104),.112,.012,11)
        for i in range(count):box(o,(-.39+i*.135,.32,.07),(.08,.16,.015),tile,.009)
    o=asset('A30','署名付きCRL一覧ボード','concept');box(o,(0,.96,0),(1.42,1.92,.07),2,.06);box(o,(0,.98,.05),(1.27,1.75,.02),7,.045);box(o,(0,1.71,.066),(.95,.074,.01),8,.012)
    for i in range(8):
        y=1.5-i*.15;box(o,(.12,y,.067),(.72,.022,.009),2,.003);box(o,(-.46,y,.072),(.072,.06,.012),8 if i==2 else 9,.01)
    cyl(o,(.38,.2,.08),.10,.027,3,rot('x',math.pi/2))
    o=asset('A31','OCSP応答ディスク','concept');cyl(o,(0,.45,0),.42,.12,1,rot('x',math.pi/2));torus(o,(0,.45,.075),.35,.019,3)
    for i,t in enumerate([12,8,13]):cyl(o,(-.20+i*.20,.45,.078),.064,.026,t,rot('x',math.pi/2))
    o=asset('A32','証明書チェーン接続環','concept')
    for i in range(3):torus(o,((i-1)*.43,.25,0),.26,.047,3 if i==2 else 2,rot('y',math.pi/2) if i%2 else None)
    o=asset('A33','TLS鍵共有の概念展示','concept');box(o,(0,.10,0),(1.8,.2,.90),1,.06)
    for x in [-.56,.56]:
        cyl(o,(x,.35,0),.16,.38,2);torus(o,(x,.82,0),.27,.026,9);sphere(o,(x,.82,0),.13,12)
    rod(o,(-.35,.82,0),(.35,.82,0),.018,3)
    o=asset('A34','発行承認バッジ','concept');cyl(o,(0,.38,0),.36,.09,3,rot('x',math.pi/2));torus(o,(0,.38,.065),.29,.015,11);rod(o,(-.15,.37,.065),(-.04,.26,.065),.025,12);rod(o,(-.04,.26,.065),(.18,.51,.065),.025,12)
    o=asset('A35','有効期限クロック','concept');cyl(o,(0,.54,0),.50,.11,2,rot('x',math.pi/2));cyl(o,(0,.54,.07),.44,.025,7,rot('x',math.pi/2))
    for i in range(12):
        a=TAU*i/12;rod(o,(.35*math.sin(a),.54+.35*math.cos(a),.092),(.40*math.sin(a),.54+.40*math.cos(a),.092),.009,1)
    rod(o,(0,.54,.101),(0,.82,.101),.016,1);rod(o,(0,.54,.111),(.22,.54,.111),.020,3)
    o=asset('A36','拒否状態の遮断パネル','concept');box(o,(0,.66,0),(1.17,1.32,.075),8,.12)
    rod(o,(-.28,.37,.055),(.28,.94,.055),.051,0);rod(o,(.28,.37,.055),(-.28,.94,.055),.051,0)
    o=asset('A37','案内・審査ロボット','character');cyl(o,(0,.09,0),.35,.18,1)
    for x in [-.23,.23]:
        box(o,(x,.21,.085),(.24,.20,.43),1,.07);cyl(o,(x,.46,0),.08,.36,2);sphere(o,(x,.60,0),.11,2)
    lathe(o,(0,0,0),[(0,.60),(.23,.60),(.32,.75),(.31,1.13),(.20,1.26),(0,1.26)],0)
    box(o,(0,.99,.31),(.30,.26,.06),1,.05);torus(o,(0,.99,.35),.085,.016,3)
    cyl(o,(0,1.30,0),.10,.13,2)
    head=o.child('head',(0,1.55,0),extras={'animated':True});sphere(head,(0,0,0),.28,0,scale=(1.15,.95,.86));box(head,(0,0,.227),(.47,.21,.073),10,.07)
    for x in [-.11,.11]:cyl(head,(x,.006,.276),.033,.018,0,rot('x',math.pi/2),mat='light_teal')
    for side in [-1,1]:
        arm=o.child('arm_'+('L' if side<0 else 'R'),(side*.33,1.09,0),extras={'animated':True});sphere(arm,(0,0,0),.10,2)
        rod(arm,(0,-.05,0),(side*.055,-.32,.035),.065,0);sphere(arm,(side*.055,-.34,.035),.075,2);rod(arm,(side*.055,-.36,.035),(side*.09,-.52,.13),.058,0)
        for f in [-1,1]:box(arm,(side*.09+f*.04,-.57,.14),(.038,.14,.11),1,.015)
    o=asset('A38','見学用ベンチ','office')
    for x in [-.82,.82]:box(o,(x,.23,0),(.11,.46,.6),1,.03)
    for z in [-.23,0,.23]:box(o,(0,.5,z),(2.1,.11,.2),6,.045)
    o=asset('A39','床配線トレイ','architecture');box(o,(0,.027,0),(2,.054,.18),2,.01)
    for i in range(12 if not LEVEL else 6):box(o,(-.9+i*1.8/(11 if not LEVEL else 5),.06,0),(.10,.014,.135),1,.004)
    o=asset('A40','証明書スタンド','concept');box(o,(0,.05,0),(.93,.10,.57),1,.035);rod(o,(0,.1,-.15),(0,.72,-.15),.035,2);box(o,(0,.34,0),(.93,.06,.16),3,.015)
    return ASSETS

class GLB:
    def __init__(self,lod=0,embedded=False,collider=False):
        self.lod=lod;self.binary=bytearray();self.accessors=[];self.views=[];self.meshes=[];self.nodes=[];self.anim=[];self.cache={}
        self.doc={'asset':{'version':'2.0','generator':'CA Trust Atlas deterministic builder 1.0','copyright':'Original procedural assets; no cryptographic key material'},'scene':0,'scenes':[{'nodes':[]}],'nodes':self.nodes,'meshes':self.meshes,'accessors':self.accessors,'bufferViews':self.views,'buffers':[{}]}
        self.materials=[{'name':'SurfaceAtlas','pbrMetallicRoughness':{'baseColorFactor':[1,1,1,1],'metallicFactor':1,'roughnessFactor':1,'baseColorTexture':{'index':0},'metallicRoughnessTexture':{'index':2}},'normalTexture':{'index':1,'scale':.65},'occlusionTexture':{'index':2,'strength':.7}}]
        self.mat_index={'atlas':0}
        self.materials.append({'name':'ExhibitGlass','alphaMode':'BLEND','doubleSided':True,'pbrMetallicRoughness':{'baseColorFactor':[.32,.63,.70,.16],'metallicFactor':0,'roughnessFactor':.15}});self.mat_index['glass']=1
        for name,color in [('light_white',[1,.92,.72]),('light_teal',[.04,.72,.67]),('light_red',[1,.12,.06])]:
            self.mat_index[name]=len(self.materials);self.materials.append({'name':name,'emissiveFactor':color,'pbrMetallicRoughness':{'baseColorFactor':color+[1],'metallicFactor':0,'roughnessFactor':.3}})
        self.doc['materials']=self.materials
        if collider:
            self.materials[0]={'name':'CollisionProxy','pbrMetallicRoughness':{'baseColorFactor':[.5,.5,.5,1],'metallicFactor':0,'roughnessFactor':1}}
        else:
            images=[];texdir=ROOT/'assets/textures'/('4k' if lod==0 else '2k')
            for name in TEX_NAMES:
                if embedded:
                    vi=self.blob((texdir/name).read_bytes());images.append({'bufferView':vi,'mimeType':'image/jpeg' if name.endswith('jpg') else 'image/png'})
                else:images.append({'uri':'../../textures/'+('4k' if lod==0 else '2k')+'/'+name})
            self.doc.update(images=images,textures=[{'source':i,'sampler':0} for i in range(3)],samplers=[{'magFilter':9729,'minFilter':9987,'wrapS':33071,'wrapT':33071}])
    def blob(self,data,target=None):
        while len(self.binary)%4:self.binary.append(0)
        v={'buffer':0,'byteOffset':len(self.binary),'byteLength':len(data)}
        if target:v['target']=target
        self.views.append(v);self.binary.extend(data);return len(self.views)-1
    def acc(self,a,kind,component=5126,target=None):
        a=np.asarray(a,dtype='<f4' if component==5126 else '<u4');view=self.blob(a.tobytes(),target)
        ac={'bufferView':view,'componentType':component,'count':len(a),'type':kind}
        if kind in ('VEC3','SCALAR'):
            ac['min']=np.atleast_1d(a.min(axis=0)).tolist();ac['max']=np.atleast_1d(a.max(axis=0)).tolist()
        self.accessors.append(ac);return len(self.accessors)-1
    def mesh(self,geom,key):
        if key in self.cache:return self.cache[key]
        prim=[]
        for mat,(v,f,n,u) in geom.items():
            pr={'attributes':{'POSITION':self.acc(v,'VEC3',target=34962),'NORMAL':self.acc(n,'VEC3',target=34962),'TEXCOORD_0':self.acc(u,'VEC2',target=34962)},'indices':self.acc(f.flatten(),'SCALAR',5125,34963),'material':self.mat_index[mat]};prim.append(pr)
        i=len(self.meshes);self.meshes.append({'name':key,'primitives':prim});self.cache[key]=i;return i
    def node(self,n,prefix='',top=False):
        name=prefix+n.name;i=len(self.nodes);d={'name':name,'translation':n.xyz,'extras':n.extras};self.nodes.append(d)
        if n.rotation:d['rotation']=n.rotation
        if n.parts:d['mesh']=self.mesh(n.geometry(),n.name+'_'+str(self.lod))
        if n.children:d['children']=[self.node(ch,prefix) for ch in n.children]
        if top:self.doc['scenes'][0]['nodes'].append(i)
        return i
    def place(self,n,name,p=(0,0,0),angle=0,scale=(1,1,1),extras=None):
        i=len(self.nodes);d={'name':name,'translation':list(p),'rotation':quat('y',angle),'scale':list(scale),'extras':extras or {}}
        self.nodes.append(d);d['children']=[self.node(n,name+'__')];self.doc['scenes'][0]['nodes'].append(i);return i
    def clip(self,name,tracks):
        channels=[];samplers=[]
        for ni,prop,times,values,interpolation in tracks:
            input=self.acc(np.asarray(times),'SCALAR');output=self.acc(np.asarray(values),'VEC4' if prop=='rotation' else 'VEC3')
            samplers.append({'input':input,'output':output,'interpolation':interpolation});channels.append({'sampler':len(samplers)-1,'target':{'node':ni,'path':prop}})
        if channels:self.anim.append({'name':name,'samplers':samplers,'channels':channels})
    def save(self,path):
        if self.anim:self.doc['animations']=self.anim
        self.doc['buffers'][0]['byteLength']=len(self.binary)
        j=json.dumps(self.doc,ensure_ascii=False,separators=(',',':')).encode();j+=b' '*((-len(j))%4)
        b=bytes(self.binary);b+=b'\0'*((-len(b))%4)
        data=struct.pack('<4sII',b'glTF',2,12+8+len(j)+8+len(b))+struct.pack('<II',len(j),0x4E4F534A)+j+struct.pack('<II',len(b),0x004E4942)+b
        Path(path).write_bytes(data)
        return {'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'mesh_triangles':sum(self.accessors[p['indices']]['count']//3 for m in self.meshes for p in m['primitives']),'nodes':len(self.nodes),'animations':[a['name'] for a in self.anim]}


def walk(n):
    yield n
    for c in n.children:yield from walk(c)

def asset_bounds(n):
    vv=[]
    def go(k,t):
        tt=t+np.array(k.xyz)
        for g in k.geometry().values():vv.append(g[0]+tt)
        for ch in k.children:go(ch,tt)
    go(n,np.zeros(3));v=np.concatenate(vv);return v.min(0).tolist(),v.max(0).tolist()

def add_local_clips(g,asset):
    node_by={n['name']:i for i,n in enumerate(g.nodes)}
    id=asset.name
    if id=='A10':g.clip('VaultDoor_Open',[(node_by['hinge'],'rotation',[0,2,3],[quat('y',0),quat('y',-1.25),quat('y',-1.25)],'LINEAR')])
    if id=='A12':g.clip('Signing_Press',[(node_by['press'],'translation',[0,.8,1.15,2],[[0,0,0],[0,-.3,0],[0,-.3,0],[0,0,0]],'LINEAR')])
    if id=='A17':g.clip('TrustDrawer_Select',[(node_by['drawer_0'],'translation',[0,1.5,3],[[0,0,0],[0,0,.4],[0,0,0]],'LINEAR')])
    if id=='A18':g.clip('Gate_Open',[(node_by['shutter_'+s],'translation',[0,1.5,2],[[0,0,0],[d*.65,0,0],[d*.65,0,0]],'LINEAR') for s,d in [('L',-1),('R',1)]])
    if id=='A26':g.clip('CSR_Read',[(node_by['cover'],'rotation',[0,1.5,3],[quat('y',0),quat('y',-2.6),quat('y',-2.6)],'LINEAR')])
    if id=='A37':g.clip('Guide_Point',[(node_by['arm_R'],'rotation',[0,1,2,3],[quat('x',0),quat('x',-1.25),quat('x',-1.25),quat('x',0)],'LINEAR')])

PLACEMENTS=[]
def layout():
    global PLACEMENTS
    PLACEMENTS=[]
    def put(id,name,p,angle=0,scale=(1,1,1),zone=''):PLACEMENTS.append({'asset_id':id,'name':name,'position':list(p),'rotation_y':angle,'scale':list(scale),'zone':zone})
    put('A01','foundation',(0,0,0),zone='architecture')
    for x in range(-13,14,2):
        for z in range(-9,10,2):put('A02',f'tile_{x}_{z}',(x,.04,z),zone='architecture')
    # Back pavilions: quiet, open-roof cross-section. Offline room has no cable run.
    zones=[('root',-10,-5,6),('issuer',-3,-5,6),('server',4,-5,5),('revocation',10.6,-4,4.4)]
    for zone,x,z,w in zones:
        for j,xx in enumerate(np.arange(x-w/2+1,x+w/2,2)):put('A03',f'{zone}_wall_{j}',(xx,.15,z-2.7),zone=zone)
        for side in [-1,1]:
            for j in [0,1]:put('A04',f'{zone}_glass_{side}_{j}',(x+side*w/2,.15,z-1.4+j*2),math.pi/2,zone=zone)
        put('A05',zone+'_portal',(x,.15,z+1.85),zone=zone)
        put('A06',zone+'_lamp',(x,3.48,z-.6),zone=zone)
    put('A09','root_vault',(-10,.16,-5.75),zone='root');put('A10','root_door',(-10,.16,-4.77),zone='root')
    put('A11','root_cradle',(-10,1,-5.48),zone='root');put('A24','private_root',(-10,1.35,-5.4),scale=(.55,.55,.55),zone='root')
    put('A08','root_offline_threshold',(-10,.17,-2.7),scale=(3.75,.025,.22),zone='root')
    put('A23','offline_case',(-11.9,.17,-3.6),zone='root');put('A37','root_keeper',(-8.65,.16,-3.85),math.pi*.10,zone='root')
    put('A12','issuer_signer',(-3,.16,-5.05),zone='issuer');put('A11','issuer_cradle',(-4.6,.16,-4.6),scale=(.6,.6,.6),zone='issuer');put('A24','private_issuer',(-4.6,.5,-4.6),scale=(.4,.4,.4),zone='issuer')
    put('A37','issuer_operator',(-1.5,.16,-4.2),-.2,zone='issuer');put('A22','issuer_audit',(-4.95,.16,-6.7),zone='issuer')
    put('A16','https_server',(4,.16,-5.2),zone='server');put('A14','server_monitor',(2.4,.7,-4.4),scale=(.8,.8,.8),zone='server');put('A08','server_desk',(2.4,.16,-4.4),zone='server');put('A11','server_cradle',(5.15,.16,-4.9),scale=(.55,.55,.55),zone='server');put('A24','private_server',(5.15,.49,-4.9),scale=(.35,.35,.35),zone='server')
    put('A20','crl_cabinet',(10.2,.16,-4.5),zone='revocation');put('A21','ocsp_kiosk',(11.8,.16,-2.8),-.22,scale=(.78,.78,.78),zone='revocation');put('A30','crl_display',(9,.16,-3.9),scale=(.65,.65,.65),zone='revocation')
    put('A13','ra_counter',(-9,.16,3.8),zone='ra');put('A14','ra_monitor',(-9.6,1.31,3.5),scale=(.70,.70,.70),zone='ra');put('A15','ra_keyboard',(-9.5,1.30,4.1),scale=(.65,.65,.65),zone='ra');put('A37','ra_reviewer',(-7.15,.16,3.4),-.3,zone='ra')
    put('A08','browser_desk',(-1,.16,3.8),scale=(1.4,1.4,1),zone='client');put('A14','browser_monitor',(-1,.93,3.7),zone='client');put('A15','browser_keyboard',(-1,.92,4.4),zone='client');put('A17','trust_store',(-3.1,.16,4.1),zone='client');put('A29','local_root_cert',(-3.1,1.78,4.13),scale=(.43,.43,.43),zone='client');put('A37','client_guide',(.7,.16,4.8),-.15,zone='client')
    # Certificate chain display: three public artifacts, not three private keys.
    for j,(cid,x) in enumerate([('A29',-2.3),('A28',-.6),('A27',1.1)]):
        put('A40','chain_stand_'+str(j),(x,.16,.15),zone='client')
        put(cid,'chain_card_'+str(j),(x,.48,.15),scale=(.60,.60,.60),zone='client')
    for j,x in enumerate([-1.45,.25]):put('A32','chain_link_'+str(j),(x,.68,.15),scale=(.5,.5,.5),zone='client')
    put('A31','ocsp_response',(11.8,2,-2.77),scale=(.46,.46,.46),zone='revocation')
    # Six conceptual checks, all inside the relying-party boundary.
    for i in range(6):put('A18','gate_'+str(i),(3.8+i*1.55,.16,4.1),math.pi/2,scale=(.85,.9,.85),zone='verification')
    put('A19','gate_checklist',(3.2,.16,5.8),zone='verification');put('A35','clock',(7.0,.20,6.2),scale=(.65,.65,.65),zone='verification');put('A33','tls_exchange',(10.8,.16,6.5),zone='verification')
    put('A38','visitor_bench',(-8,.16,7.8),zone='ra');put('A38','client_bench',(-.7,.16,7.8),zone='client')
    for x in [-4.5,-2.5,-.5,1.5,3.5,5.5,7.5,9.5,11.5]:put('A39','conduit_'+str(x),(x,.17,-1.85),zone='public_data')
    for x in [-4.8,1.8,12.7]:
        for z in [2.0,6.5]:put('A07',f'boundary_{x}_{z}',(x,.16,z),zone='client')
    for id,name,p in [('A26','actor_csr',(4,1.7,-4)),('A27','actor_leaf',(-3,1.9,-4)),('A28','actor_intermediate',(-3,1.8,-5)),('A30','actor_crl',(10.2,2.2,-4)),('A25','actor_public',(4.5,2.2,-4)),('A34','actor_approval',(-7.6,1.7,3.6)),('A36','actor_reject',(10,.5,4.1))]:put(id,name,p,scale=(.00001,)*3,zone='actors')
    return PLACEMENTS

def bake_lesson(g):
    ids={n['name']:i for i,n in enumerate(g.nodes)};tr=[];tiny=[.00001]*3
    def scale(name,start,end,s):
        times=[0,max(.01,start),start+.4,end,end+.4,180]
        vals=[tiny,tiny,[s]*3,[s]*3,tiny,tiny];tr.append((ids[name],'scale',times,vals,'LINEAR'))
    scale('actor_csr',40,74,.65)
    tr.append((ids['actor_csr'],'translation',[0,40,49,60,70,75,180],[[4,1.8,-4],[4,1.8,-4],[-9,1.65,3.8],[-9,1.65,3.8],[-3,1.75,-4.8],[-3,1.75,-4.8],[-3,1.75,-4.8]],'LINEAR'))
    scale('actor_public',31,40,.5);scale('actor_approval',61,70,.55)
    tr.append((ids['actor_leaf'],'scale',[0,75,75.4,158,158.4,170,170.4,180],[tiny,tiny,[.6]*3,[.6]*3,tiny,tiny,[.6]*3,[.6]*3],'LINEAR'))
    tr.append((ids['actor_intermediate'],'scale',[0,10,10.4,19,19.4,90,90.4,103,103.4,180],[tiny,tiny,[.5]*3,[.5]*3,tiny,tiny,[.45]*3,[.45]*3,tiny,tiny],'LINEAR'))
    tr.append((ids['actor_intermediate'],'translation',[0,10,19,90,99,104,180],[[-10,2.1,-4.2],[-10,2.1,-4.2],[-3,2.1,-4.2],[4.45,1.8,-4.2],[-.55,1.7,3.8],[3.7,1.4,4.1],[3.7,1.4,4.1]],'LINEAR'))
    # Hold before each local check; cross its plane only after PASS at 107+10*i.
    leaf_times=[0,75,80,89,99]
    leaf_values=[[-3,1.75,-4.8],[-3,1.75,-4.8],[4,1.5,-4.2],[4,1.5,-4.2],[-1,1.4,3.8]]
    for i in range(6):
        gx=3.8+i*1.55
        leaf_times.extend([103+i*10,107+i*10,109+i*10])
        leaf_values.extend([[gx-.6,1.05,4.1],[gx-.6,1.05,4.1],[gx+.45,1.05,4.1]])
    leaf_times.extend([169,170,172,175,180]);leaf_values.extend([[12,1.05,4.1],[4,1.5,-4.2],[-1,1.4,3.8],[9.4,1.05,4.1],[9.4,1.05,4.1]])
    tr.append((ids['actor_leaf'],'translation',leaf_times,leaf_values,'LINEAR'))

    scale('actor_crl',161,177,.6);tr.append((ids['actor_crl'],'translation',[0,161,169,180],[[10.2,2,-4],[10.2,2,-4],[10,1.15,4.1],[10,1.15,4.1]],'LINEAR'))
    scale('actor_reject',174,179.5,.8)
    tr.append((ids['issuer_signer__press'],'translation',[0,71,74,76,79,180],[[0,0,0],[0,0,0],[0,-.3,0],[0,-.3,0],[0,0,0],[0,0,0]],'LINEAR'))
    tr.append((ids['actor_csr__cover'],'rotation',[0,49,53,68,73,180],[quat('y',0),quat('y',0),quat('y',-2.6),quat('y',-2.6),quat('y',0),quat('y',0)],'LINEAR'))
    tr.append((ids['trust_store__drawer_0'],'translation',[0,21,24,28,30,180],[[0,0,0],[0,0,0],[0,0,.4],[0,0,.4],[0,0,0],[0,0,0]],'LINEAR'))
    for who,start in [('root_keeper',11),('issuer_operator',71),('ra_reviewer',55),('client_guide',101)]:
        tr.append((ids[who+'__arm_R'],'rotation',[0,start,start+1,start+4,start+6,180],[quat('x',0),quat('x',0),quat('x',-1.25),quat('x',-1.25),quat('x',0),quat('x',0)],'LINEAR'))
    for i in range(6):
        for side,sign in [('L',-1),('R',1)]:
            st=100+i*10
            tr.append((ids[f'gate_{i}__shutter_{side}'],'translation',[0,st,st+7,160,170,180],[[0,0,0],[0,0,0],[sign*.65,0,0],[sign*.65,0,0],[0,0,0],[0,0,0]],'LINEAR'))
    g.clip('CA_Lesson_180s_SIMULATED',tr)


def build():
    texture_atlas();manifest=[];files=[];layout()
    for lev in [0,1]:
        assets=make_assets(lev);lookup={id:n for id,title,cat,n in assets}
        for id,title,cat,n in assets:
            g=GLB(lev);g.node(n,top=True);add_local_clips(g,n);p=ROOT/f'assets/models/lod{lev}/{id}.glb';info=g.save(p);files.append(str(p.relative_to(ROOT)))
            if lev==0:
                mn,mx=asset_bounds(n);manifest.append({'id':id,'name_ja':title,'category':cat,'bounds_min':mn,'bounds_max':mx,'dimensions_m':(np.array(mx)-mn).round(4).tolist(),'lod0':info,'paths':{'lod0':str(p.relative_to(ROOT))},'pbr':'shared 4096x4096 atlas; external images','collider':{'type':'aabb','min':mn,'max':mx}})
            else:
                row=next(x for x in manifest if x['id']==id);row['lod1']=info;row['paths']['lod1']=str(p.relative_to(ROOT))
        g=GLB(lev,embedded=True)
        for obj in PLACEMENTS:g.place(lookup[obj['asset_id']],obj['name'],obj['position'],obj['rotation_y'],obj['scale'],{'zone':obj['zone'],'asset_id':obj['asset_id'],'animated':obj['zone']=='actors'})
        bake_lesson(g);p=ROOT/f'assets/scenes/ca_atlas_{"hero" if not lev else "runtime"}.glb';info=g.save(p)
        (ROOT/'data'/f'scene_{lev}_stats.json').write_text(json.dumps(info,indent=2),encoding='utf-8')
    (ROOT/'data/assets.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
    (ROOT/'data/layout.json').write_text(json.dumps({'coordinate_system':'+Y up, metres, +Z front','extent_m':[28,20],'placements':PLACEMENTS},ensure_ascii=False,indent=2),encoding='utf-8')
    with (ROOT/'docs/asset-bom.csv').open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.writer(f);w.writerow(['ID','モデル','分類','幅m','高m','奥行m','LOD0三角形','LOD1三角形','GLB内クリップ','LOD0 GLB'])
        for a in manifest:w.writerow([a['id'],a['name_ja'],a['category'],*a['dimensions_m'],a['lod0']['mesh_triangles'],a['lod1']['mesh_triangles'],';'.join(a['lod0']['animations']),a['paths']['lod0']])
    # Collision proxies are supplied for layout integration, not an implemented walking controller.
    g=GLB(1,collider=True)
    for a in manifest:
        if a['category'] in ['concept','character']:continue
        o=Node(a['id']+'_collider');mn=np.array(a['bounds_min']);mx=np.array(a['bounds_max']);box(o,(mn+mx)/2,np.maximum(mx-mn,.01),r=0)
        for obj in PLACEMENTS:
            if obj['asset_id']==a['id']:g.place(o,obj['name']+'_collider',obj['position'],obj['rotation_y'],obj['scale'])
    g.save(ROOT/'assets/scenes/collision-proxies.glb')
    print('BUILT',len(manifest),'master assets',len(PLACEMENTS),'placements')
    print('Triangles LOD0',sum(a['lod0']['mesh_triangles'] for a in manifest),'LOD1',sum(a['lod1']['mesh_triangles'] for a in manifest))
if __name__=='__main__':build()
