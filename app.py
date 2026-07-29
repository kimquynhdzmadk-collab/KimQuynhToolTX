"""MD5 TAI/XIU API - 85 deterministic algorithms"""
import math,time,os,json
from flask import Flask,request,jsonify
from flask_cors import CORS
from collections import Counter

app=Flask(__name__);CORS(app);ST=time.time()
def h2b(h):return[int(h[i:i+2],16)for i in range(0,32,2)]
def nib(h):return[int(c,16)for c in h]
def h2s(h):
 s=0
 for c in h:s=((s<<5)-s+ord(c))&0xFFFFFFFF
 return abs(s)
def mean(a):return sum(a)/len(a)if a else 0
def stdv(a):
 m=mean(a)
 return math.sqrt(sum((x-m)**2 for x in a)/len(a))if a else 0
def clamp(v,lo=0,hi=1):return max(lo,min(hi,v))
def lv(a,N,v):
 s=a[-N:];return sum(1 for x in s if x==v)/max(1,len(s))
def sma(a,w):
 r=[]
 for i in range(len(a)):r.append(mean(a[max(0,i-w+1):i+1]))
 return r
def ema(a,w):
 alpha=2/(w+1);r=[a[0]]
 for i in range(1,len(a)):r.append(alpha*a[i]+(1-alpha)*r[-1])
 return r
def ptr(a):
 if len(a)<2:return'TAI'
 return'TAI'if a[-1]>a[-2]else'XIU'
def dmd5(h):
 bs,ns=h2b(h),nib(h);res=[]
 xp=0
 for i in range(0,16,2):xp^=(bs[i]<<8)|bs[i+1]
 res.append({'n':'XOR Byte Pairs','r':'TAI'if xp&0x8000 else'XIU','v':hex(xp)})
 ps=sum(ns);res.append({'n':'Parity Sum','r':'TAI'if ps%2==0 else'XIU','v':ps})
 hc=sum(1 for n in ns if n>=8);lc=32-hc
 res.append({'n':'Hex Dist H/L','r':'TAI'if hc>=lc else'XIU','v':f'H:{hc} L:{lc}'})
 ra=0
 for n in ns:ra=((ra<<1)|(ra>>31))^n
 res.append({'n':'Bitwise Rotation','r':'TAI'if ra&1 else'XIU','v':ra})
 crc=0xFFFF
 for b in bs:
  crc^=b
  for _ in range(8):crc=((crc>>1)^0xA001)if(crc&1)else(crc>>1)
 res.append({'n':'CRC16','r':'TAI'if crc&1 else'XIU','v':crc})
 fr=Counter(ns);ent=-sum((c/32)*math.log2(c/32)for c in fr.values())
 res.append({'n':'Shannon Entropy','r':'TAI'if ent>3.5 else'XIU','v':round(ent,4)})
 fib=[1,1,2,3,5,8,13,21];fx=0
 for idx in fib:
  if idx<32:fx^=ns[idx]
 res.append({'n':'Fibonacci XOR','r':'TAI'if fx&1 else'XIU','v':fx})
 rr=0
 for n in ns:rr=((rr<<3)|(rr>>29))^(n&0xF)
 res.append({'n':'Bit Rot Accum','r':'TAI'if rr&0x80000000 else'XIU','v':rr})
 hd=0
 for i in range(16):
  xv=ns[i]^ns[i+16]
  while xv:hd+=xv&1;xv>>=1
 res.append({'n':'Hamming Half','r':'TAI'if hd>=32 else'XIU','v':hd})
 return res
def gendata(h):
 ns=nib(h);seed=h2s(h);cnt=40+(ns[0]%21);res=[]
 s=seed
 for i in range(cnt):
  s=(s*1103515245+12345)&0x7FFFFFFF;nv=ns[i%32];pf=(i*7+nv*13+seed)%256
  it=(pf&1)==0;sc=11+((pf>>1)%8)if it else 4+((pf>>1)%7)
  res.append({'i':i+1,'r':'TAI'if it else'XIU','s':sc})
 return res
def ahs(h):
 bs=h2b(h);ns=nib(h);res=[]
 ac=sum(1 for b in bs if 32<=b<=126)
 res.append({'n':'ASCII Pattern','r':'TAI'if ac>=6 else'XIU','v':f'{ac}/16'})
 hc=sum(1 for b in bs if b>=128)
 res.append({'n':'High Byte Count','r':'XIU'if hc>=4 else'TAI','v':f'{hc}/16'})
 av=sum(((ns[i]^ns[i+16])&0xF)/(i+1)*16 for i in range(16))
 res.append({'n':'Avalanche Score','r':'TAI'if av>30 else'XIU','v':round(av,2)})
 lb=((bs[14]<<8)|bs[15])*8
 res.append({'n':'Input Length Est','r':'TAI'if lb%2==0 else'XIU','v':f'~{lb} bits'})
 kn=['d41d8cd98f00b204e9800998ecf8427e','5d41402abc4b2a76b9719d911017c592','098f6bcd4621d373cade4e832627b4f6']
 md=min(sum(abs(int(h[i],16)-int(kp[i],16))for i in range(32))for kp in kn)
 res.append({'n':'Known Pattern Dist','r':'TAI'if md>40 else'XIU','v':md})
 mc=cu=0
 for i in range(1,32):
  if h[i]==h[i-1]:cu+=1
  else:mc=max(mc,cu);cu=0
 res.append({'n':'Max Repeated Nibbles','r':'XIU'if mc>2 else'TAI','v':mc})
 res.append({'n':'First Byte','r':'XIU'if bs[0]>=128 else'TAI','v':hex(bs[0])})
 res.append({'n':'Byte Sum mod 256','r':'TAI'if sum(bs)%256>=128 else'XIU','v':sum(bs)%256})
 return res
def rsi(a,w):
 ch=[a[i]-a[i-1]for i in range(1,len(a))];r=[]
 for i in range(w,len(ch)):
  g=sum(max(0,ch[j])for j in range(i-w,i));l=sum(max(0,-ch[j])for j in range(i-w,i))
  l=max(l,0.001);r.append(100-(100/(1+g/l)))
 return r
def cp(a,pat):
 p=[1 if c=='T'else 0 for c in pat]
 if len(a)<len(p):return False
 for i in range(len(p)):
  if a[-len(p)+i]!=p[i]:return False
 return True
def runalgo(data,h):
 al=[];n=len(data);seq=[1 if d['r']=='TAI'else 0 for d in data];ft=sum(seq);fx=n-ft
 def A(nm,g,p,c):al.append({'n':nm,'g':g,'p':p,'c':round(clamp(c),4)})
 A('Frequency','stat','TAI'if ft>fx else'XIU',abs(ft/n-0.5)*2)
 stre=1
 for i in range(n-2,-1,-1):
  if seq[i]==seq[-1]:stre+=1
  else:break
 A('Streak','stat','TAI'if seq[-1]else'XIU',stre/8)
 alt=sum(1 for i in range(1,n)if seq[i]!=seq[i-1]);ar=alt/(n-1)
 A('Alternation','stat',('XIU'if seq[-1]else'TAI')if ar>0.5 else('TAI'if seq[-1]else'XIU'),abs(ar-0.5)*2)
 ch=sum(1 for i in range(1,n)if seq[i]!=seq[i-1])+1
 A('Chunks','stat',('XIU'if seq[-1]else'TAI')if ch>n/3 else('TAI'if seq[-1]else'XIU'),0.55)
 mx,cx=1,1
 for i in range(1,n):
  if seq[i]==seq[i-1]:cx+=1;mx=max(mx,cx)
  else:cx=1
 A('MaxRun','stat',('XIU'if seq[-1]else'TAI')if mx>5 else('TAI'if seq[-1]else'XIU'),0.6)
 w10=lv(seq,10,1);A('WFreq10','stat','TAI'if w10>0.5 else'XIU',abs(w10-0.5)*2)
 w20=lv(seq,20,1);A('WFreq20','stat','TAI'if w20>0.5 else'XIU',abs(w20-0.5)*2)
 t2t=sum(1 for i in range(1,n)if seq[i-1]and seq[i]);t2x=sum(1 for i in range(1,n)if seq[i-1]and not seq[i])
 x2t=sum(1 for i in range(1,n)if not seq[i-1]and seq[i])
 ts2=t2t+t2x;tp2=t2t/ts2 if ts2 else 0.5
 if seq[-1]:A('TransMatrix','stat','TAI'if tp2>0.5 else'XIU',abs(tp2-0.5)*2)
 else:xs2=x2t+sum(1 for i in range(1,n)if not seq[i-1]and not seq[i]);xp2=x2t/xs2 if xs2 else 0.5;A('TransMatrix','stat','TAI'if xp2>0.5 else'XIU',abs(xp2-0.5)*2)
 lt=n;lx=n
 for i in range(n-2,-1,-1):
  if seq[i]and lt==n:lt=n-1-i
  if not seq[i]and lx==n:lx=n-1-i
 A('LastOcc','stat','XIU'if lt<lx else'TAI',0.55)
 tr=0;xr=0;cr=seq[0];crl=1
 for i in range(1,n):
  if seq[i]==cr:crl+=1
  else:
   if cr:tr+=crl
   else:xr+=crl
   cr=seq[i];crl=1
 if cr:tr+=crl
 else:xr+=crl
 rr2=tr/max(1,xr);A('RunRatio','stat','TAI'if rr2>1 else'XIU',abs(rr2-1)/2)
 gi=abs(tr-xr)/(tr+xr)if(tr+xr)else 0;A('Gini','stat','TAI'if gi>0.2 else'XIU',gi)
 w2=[0.5,0.3,0.2];ws=sum(seq[n-1-i]*w2[i]for i in range(3)if n-1-i>=0);wsm=sum(w2[i]for i in range(3)if n-1-i>=0)
 A('WtLast3','stat','TAI'if ws/wsm>0.5 else'XIU',0.6)
 A('Momentum','stat','TAI'if sum(seq[-5:])>=3 else'XIU',0.6)
 for w,cf in[(3,0.55),(5,0.56),(7,0.57),(10,0.58),(14,0.59),(20,0.6),(30,0.61)]:s=sma(seq,w);A(f'SMA{w}','tech',ptr(s),cf)
 for w,cf in[(5,0.56),(8,0.57),(12,0.58),(21,0.59),(26,0.6)]:e=ema(seq,w);A(f'EMA{w}','tech',ptr(e),cf)
 em12=ema(seq,12);em26=ema(seq,26);mc=[em12[i]-em26[i]for i in range(len(em12))]
 sg=ema(mc,9);mh=[mc[i]-sg[i]for i in range(len(mc))]
 A('MACD','tech',ptr(mc),0.62);A('MACD SigX','tech','TAI'if mc[-1]>sg[-1]else'XIU',0.63);A('MACD Hist','tech','TAI'if mh[-1]>0 else'XIU',0.61)
 rs6=rsi(seq,6);A('RSI6','tech','TAI'if rs6 and rs6[-1]>50 else'XIU',0.62)
 rs14=rsi(seq,14);A('RSI14','tech','TAI'if rs14 and rs14[-1]>50 else'XIU',0.63)
 bbM=sma(seq,20);bbS=[stdv(seq[max(0,i-20+1):i+1])for i in range(n)]
 bbU=[bbM[i]+2*bbS[i]for i in range(n)];bbL=[bbM[i]-2*bbS[i]for i in range(n)];bbW=[bbU[i]-bbL[i]for i in range(n)]
 bbP=[(seq[i]-bbL[i])/max(bbW[i],0.001)for i in range(n)]
 A('Bollinger','tech','TAI'if seq[-1]>bbM[-1]else'XIU',0.6);A('BB %B','tech','TAI'if bbP[-1]>0.5 else'XIU',0.58)
 kM=ema(seq,20);atV=[abs(seq[i]-seq[i-1])for i in range(1,n)];atE=ema(atV,10)
 def kv(i):
  if i<len(atE):return atE[i]
  elif i<len(atV):return atV[i]
  return 0.1
 kU=[kM[i]+1.5*kv(i)for i in range(n)];kL=[kM[i]-1.5*kv(i)for i in range(n)]
 A('Keltner','tech','TAI'if seq[-1]>kM[-1]else'XIU',0.6)
 kp=14;stK=[]
 for i in range(kp-1,n):sl=seq[i-kp+1:i+1];hi,lo=max(sl),min(sl);stK.append((seq[i]-lo)/max(hi-lo,0.001)*100)
 A('StochK','tech','TAI'if stK and stK[-1]>50 else'XIU',0.6)
 stD=sma(stK,3);A('StochD','tech','TAI'if stD and stD[-1]>50 else'XIU',0.58)
 m5=[seq[i]-seq[i-5]for i in range(5,n)];A('Mom5','tech','TAI'if m5 and m5[-1]>0 else'XIU',0.57)
 m10=[seq[i]-seq[i-10]for i in range(10,n)];A('Mom10','tech','TAI'if m10 and m10[-1]>0 else'XIU',0.58)
 rc5=[seq[i]/max(seq[i-5],0.001)for i in range(5,n)];A('ROC5','tech','TAI'if rc5 and rc5[-1]>1 else'XIU',0.55)
 rc10=[seq[i]/max(seq[i-10],0.001)for i in range(10,n)];A('ROC10','tech','TAI'if rc10 and rc10[-1]>1 else'XIU',0.56)
 atA=[abs(seq[i]-seq[i-1])for i in range(1,n)];atS=sma(atA,14)
 A('ATR14','tech','TAI'if atS and atS[-1]>mean(atS)else'XIU',0.54)
 zM,zS=mean(seq),stdv(seq);zSc=(seq[-1]-zM)/max(zS,0.001)
 A('ZScore','tech','TAI'if zSc>0 else'XIU',abs(zSc)/3)
 vn=sum(seq[i]*((i+1)%5+1)for i in range(n));vd=sum(((i+1)%5+1)for i in range(n));vw=vn/vd if vd else 0.5
 A('VWAP','tech','TAI'if seq[-1]>vw else'XIU',0.57)
 A('TTMSqz','tech',('XIU'if seq[-1]else'TAI')if bbW[-1]<(kU[-1]-kL[-1])else('TAI'if seq[-1]else'XIU'),0.55)
 tpS=sma(seq,20);tpM=[mean([abs(v-mean(seq[max(0,i-20+1):i+1]))for v in seq[max(0,i-20+1):i+1]])for i in range(n)]
 ccv=(seq[-1]-tpS[-1])/max(0.015*tpM[-1],0.001)if tpM[-1]else 0;A('CCI20','tech','TAI'if ccv>0 else'XIU',abs(ccv)/200)
 dp=[max(0,seq[i]-seq[i-1])for i in range(1,n)];dm=[max(0,seq[i-1]-seq[i])for i in range(1,n)]
 tv=[abs(seq[i]-seq[i-1])for i in range(1,n)];a14=sma(tv,14)
 ds=sma(dp,14);ms=sma(dm,14)
 dip=[ds[i]/max(a14[i],0.001)*100 if i<len(a14)else 0 for i in range(min(len(ds),len(a14)))]
 dim=[ms[i]/max(a14[i],0.001)*100 if i<len(a14)else 0 for i in range(min(len(ms),len(a14)))]
 A('ADX14','tech','TAI'if dip[-1]>dim[-1]else'XIU',0.58)
 wr=[]
 for i in range(13,n):sl=seq[i-13:i+1];h,l=max(sl),min(sl);wr.append((h-seq[i])/max(h-l,0.001)*-100)
 A('Wms%R','tech','TAI'if wr and wr[-1]>-50 else'XIU',0.57)
 obv=sum(1 if seq[i]>seq[i-1]else(-1 if seq[i]<seq[i-1]else 0)for i in range(1,n))
 A('OBV','tech','TAI'if obv>0 else'XIU',0.55)
 adl=sum(seq[i]-seq[i-1]for i in range(1,n));A('ADL','tech','TAI'if adl>0 else'XIU',0.54)
 e1=ema(seq,10);e2=ema(e1,10);dem=[2*e1[i]-e2[i]for i in range(len(e1))]
 A('DEMA','tech',ptr(dem),0.58)
 e3=ema(e2,10);tem=[3*e1[i]-3*e2[i]+e3[i]for i in range(len(dem))]
 A('TEMA','tech',ptr(tem),0.59)
 wh=sma(seq,5);wf=sma(seq,10);hm=[2*wh[i]-(wf[i]if i<len(wf)else wh[i])for i in range(len(wh))]
 A('HullMA','tech',ptr(hm),0.58)
 A('IchiTenk','tech','TAI'if seq[-1]>mean(seq[-9:])else'XIU',0.56)
 sv,af,ep=seq[0],0.02,seq[0];isL=seq[0]>0.5
 for i in range(1,n):
  sv=sv+af*(ep-sv)
  if isL:
   if seq[i]<sv:isL=False;sv=ep;ep=seq[i];af=0.02
   elif seq[i]>ep:ep=seq[i];af=min(af+0.02,0.2)
  else:
   if seq[i]>sv:isL=True;sv=ep;ep=seq[i];af=0.02
   elif seq[i]<ep:ep=seq[i];af=min(af+0.02,0.2)
 A('ParSAR','tech','TAI'if isL else'XIU',0.57)
 adv=[seq[0]]
 for i in range(1,n):adv.append(adv[-1]+(seq[i]-seq[i-1]))
 ce3=ema(adv,3);ce10=ema(adv,10);ck=[ce3[i]-ce10[i]for i in range(len(ce3))]
 A('Chaikin','tech',ptr(ck),0.56)
 def mk(o):
  mp={}
  for i in range(o,n):
   k=''.join(str(v)for v in seq[i-o:i]);v=seq[i]
   if k not in mp:mp[k]=[0,0]
   mp[k][v]+=1
  lk=''.join(str(v)for v in seq[n-o:]);e=mp.get(lk,[1,1])
  return('TAI'if e[1]>=e[0]else'XIU'),clamp(e[1]/max(e[0]+e[1],0.001))
 for o in[1,2,3]:p,c=mk(o);A(f'MkvO{o}','markov',p,c)
 hT=[[0.7,0.3],[0.3,0.7]];hn=hT[seq[-1]][0]>hT[seq[-1]][1]
 A('HMM','markov','TAI'if hn else'XIU',max(hT[seq[-1]]))
 bp=ft/n;bl=sum(seq[-3:])/3;bpo=0.3*bp+0.7*bl
 A('BayesCh','markov','TAI'if bpo>0.5 else'XIU',abs(bpo-0.5)*2)
 vit=[0]
 for i in range(1,n):
  p0=hT[vit[-1]][0]*(0.6 if seq[i]else 0.4);p1=hT[vit[-1]][1]*(0.4 if seq[i]else 0.6)
  vit.append(0 if p0>p1 else 1)
 vp=0 if hT[vit[-1]][0]>hT[vit[-1]][1]else 1;A('Viterbi','markov','TAI'if vp else'XIU',0.62)
 A('1-2-1','pattern','TAI'if cp(seq,'TXXT')else('XIU'if cp(seq,'XTTX')else('TAI'if seq[-1]else'XIU')),0.6)
 A('BetBrk','pattern',('XIU'if seq[-1]else'TAI')if stre>=4 else('TAI'if seq[-1]else'XIU'),0.62)
 A('Dao1-1','pattern','TAI'if seq[-1]!=seq[-2]else('TAI'if seq[-2]else'XIU'),0.55)
 A('2-2-2','pattern',('XIU'if seq[-1]else'TAI')if cp(seq,'TTXXTT')or cp(seq,'XXTTXX')else('TAI'if seq[-1]else'XIU'),0.58)
 A('GapDet','pattern','TAI'if seq[-3]and seq[-1]!=seq[-3]and seq[-2]==seq[-3]else('XIU'if not seq[-3]and seq[-1]!=seq[-3]and seq[-2]==seq[-3]else('TAI'if seq[-1]else'XIU')),0.56)
 A('1-3-1','pattern','XIU'if cp(seq,'TXXXT')else('TAI'if cp(seq,'XTTTX')else('TAI'if seq[-1]else'XIU')),0.59)
 A('3-2-1','pattern','XIU'if cp(seq,'TTTXXT')else('TAI'if cp(seq,'XXXTTX')else('TAI'if seq[-1]else'XIU')),0.58)
 A('DblBridge','pattern','XIU'if cp(seq,'TXXTT')else('TAI'if cp(seq,'XTTXX')else('TAI'if seq[-1]else'XIU')),0.57)
 A('TripleRep','pattern',('TAI'if seq[-1]else'XIU')if stre>=3 else('XIU'if seq[-1]else'TAI'),0.6)
 A('Zigzag','pattern','TAI'if seq[-2]and seq[-1]==seq[-3]else('XIU'if not seq[-2]and seq[-1]==seq[-3]else('TAI'if seq[-1]else'XIU')),0.55)
 A('FibRetr','pattern',('TAI'if ft>fx else'XIU')if seq[-1]else('XIU'if fx>ft else'TAI'),0.54)
 A('Mirror','pattern','TAI'if seq[-1]==seq[-5]else('XIU'if seq[-1]else'TAI'),0.56)
 A('AntiStr','pattern',('XIU'if seq[-1]else'TAI')if stre>=5 else('TAI'if seq[-1]else'XIU'),0.63)
 A('Lst2Cons','pattern','TAI'if seq[-1]==seq[-2]else('XIU'if seq[-1]else'TAI'),0.58)
 A('QuadP','pattern','XIU'if cp(seq,'TTTTXXX')else('TAI'if cp(seq,'XXXXTTT')else('TAI'if seq[-1]else'XIU')),0.57)
 hf=n//2;sym=sum(1 for i in range(hf)if seq[i]==seq[n-1-i])
 A('Symmetry','pattern','TAI'if sym>hf/2 else'XIU',sym/hf)
 de=0;te=1
 if n>=8:
  def dft(a):
   N=len(a);m=mean(a);nm=[v-m for v in a];mg=[]
   for k in range(N//2):
    re=sum(nm[n2]*math.cos(2*math.pi*k*n2/N)for n2 in range(N))
    im=-sum(nm[n2]*math.sin(2*math.pi*k*n2/N)for n2 in range(N))
    mg.append(math.sqrt(re*re+im*im))
   return mg
  dm2=dft(seq);mi=dm2.index(max(dm2));dp=n/mi if mi>0 else n
  de=dm2[mi]**2;te=sum(v**2 for v in dm2)
  A('DomPeriod','fourier','TAI'if dp%2==0 else'XIU',0.6)
  A('SpecDom','fourier','TAI'if de/te>0.7 else'XIU',de/te)
  def acf(a,lag):
   m=mean(a);num=sum((a[i]-m)*(a[i+lag]-m)for i in range(len(a)-lag))
   den=sum((a[i]-m)**2 for i in range(len(a)))
   return num/den if den else 0
  ac1=acf(seq,1);A('AutoCorrL1','fourier','TAI'if ac1>0 else'XIU',abs(ac1))
  ac2=acf(seq,2);A('AutoCorrL2','fourier','TAI'if ac2>0 else'XIU',abs(ac2))
  gm=math.exp(mean([math.log(v+0.001)for v in dm2]));am=mean(dm2);sf2=gm/am if am else 0
  A('SpecFlat','fourier','TAI'if sf2>0.5 else'XIU',sf2)
  zcr=sum(1 for i in range(1,n)if seq[i]!=seq[i-1])/(n-1)
  A('ZCR','fourier','XIU'if zcr>0.5 else'TAI',abs(zcr-0.5)*2)
  sn=sum(k*dm2[k]for k in range(len(dm2)));sd=sum(dm2);sc=sn/sd if sd else 0
  A('SpecCent','fourier','TAI'if sc>len(dm2)/2 else'XIU',0.55)
  mid=len(dm2)//2;le=sum(v**2 for v in dm2[:mid]);he=sum(v**2 for v in dm2[mid:])
  wr2=he/(le+he)if(le+he)else 0.5
  A('Wavelet','fourier',('XIU'if seq[-1]else'TAI')if wr2>0.5 else('TAI'if seq[-1]else'XIU'),0.58)
 else:
  for nm in['DomPeriod','SpecDom','AutoCorrL1','AutoCorrL2','SpecFlat','ZCR','SpecCent','Wavelet']:A(nm,'fourier','TAI'if seq[-1]else'XIU',0.5)
 return al

@app.route('/api/health')
def health():return jsonify({'status':'ok','uptime':round(time.time()-ST,2),'version':'3.0.0','algos':85})

@app.route('/api/predict',methods=['POST'])
def predict():
 d=request.get_json(silent=True)or{};h=(d.get('hash')or d.get('md5')or'').strip().lower()
 if not h or len(h)!=32 or not all(c in'0123456789abcdef'for c in h):
  return jsonify({'error':'Invalid MD5 hash'}),400
 t0=time.time()
 dc=dmd5(h);hs=ahs(h);sd=gendata(h);al=runalgo(sd,h)
 gr={};tt=tx=0
 gw={'stat':1.0,'tech':1.15,'markov':1.3,'pattern':1.2,'fourier':1.05}
 wt=wx=0
 for a in al:
  g=a['g']
  if g not in gr:gr[g]={'t':0,'x':0,'tot':0}
  gr[g]['tot']+=1
  if a['p']=='TAI':gr[g]['t']+=1;tt+=1;wt+=gw.get(g,1.0)
  else:gr[g]['x']+=1;tx+=1;wx+=gw.get(g,1.0)
 mp='TAI'if tt>=tx else'XIU';wp='TAI'if wt>=wx else'XIU'
 cf=round(max(tt,tx)/len(al)*100,1)
 el=round((time.time()-t0)*1000,2)
 return jsonify({'hash':h,'prediction':mp,'weighted_prediction':wp,'confidence':cf,
  'total_algos':len(al),'tai_votes':tt,'xiu_votes':tx,
  'time_ms':el,'data':{'algos':al}})

@app.route('/')
def idx():return jsonify({'service':'MD5 TAI/XIU API','version':'3.0.0','algos':85})

if __name__=='__main__':
 import os
 p=int(os.environ.get('PORT',5000))
 app.run(host='0.0.0.0',port=p,debug=False)
