import numpy as np, pandas as pd, json, re

# ======================================================================
# Cybersecurity Threat Intelligence Dashboard - data generation + cleaning
# Coverage: 2020-2026.   2020-2024 = original batch (seed 2026, unchanged)
#                        2025-2026 = extension batch (seed 2027)
# 2026 is a year-to-date extract: incidents detected 1 Jan - 30 Sep 2026.
# ======================================================================

BATCHES = [   # (seed, years, incidents per year, months with data per year, first incident number)
    (2026, [2020,2021,2022,2023,2024], {2020:7200, 2021:8400, 2022:10000, 2023:12000, 2024:14000}, {}, 1),
    (2027, [2025,2026],                {2025:16000, 2026:12600},                                  {2026:9}, 51601),
]
YEARS = [2020,2021,2022,2023,2024,2025,2026]
CATS = ["Phishing","Malware","Ransomware","DDoS","Insider Threat","Web App Attack"]
SUBS = {
 "Phishing":["Email Phishing","Spear Phishing","Smishing","Vishing"],
 "Malware":["Trojan","Worm","Spyware","Botnet"],
 "Ransomware":["Crypto Ransomware","Locker Ransomware","Double Extortion"],
 "DDoS":["Volumetric","Protocol Attack","Application Layer"],
 "Insider Threat":["Data Exfiltration","Privilege Misuse","Negligence"],
 "Web App Attack":["SQL Injection","Cross-Site Scripting","Credential Stuffing"],
}
SUBW = {"Phishing":[.5,.25,.15,.10],"Malware":[.35,.2,.25,.2],"Ransomware":[.45,.2,.35],
        "DDoS":[.4,.25,.35],"Insider Threat":[.4,.25,.35],"Web App Attack":[.3,.3,.4]}
W20 = np.array([.30,.24,.12,.12,.08,.14]); W24 = np.array([.27,.17,.22,.13,.08,.13])
COUNTRIES = ["China","Russia","United States","India","Brazil","Iran","North Korea","Ukraine","Germany","Nigeria","Vietnam","Turkey"]
CW = np.array([18,16,12,8,7,7,6,5,4,5,4,4],float); CW/=CW.sum()
INDS = ["Healthcare","Finance","Education","Government","E-commerce","Energy","Manufacturing","IT & Telecom"]
IW = np.array([.16,.19,.10,.12,.14,.07,.09,.13])
DSRC = ["SIEM","EDR","IDS/IPS","Threat Intel Feed","User Report","Firewall"]
DW = np.array([.30,.24,.18,.12,.10,.06])
SEV = ["Low","Medium","High","Critical"]
SEVW = {"Phishing":[.30,.42,.22,.06],"Malware":[.18,.38,.30,.14],"Ransomware":[.02,.12,.40,.46],
        "DDoS":[.20,.40,.28,.12],"Insider Threat":[.12,.34,.34,.20],"Web App Attack":[.18,.40,.28,.14]}
TEAMS = ["SOC Alpha","SOC Bravo","SOC Charlie","Threat Hunting"]
MONTH_MULT0 = np.array([.92,.88,.97,.96,1.0,.98,.95,1.0,1.05,1.08,1.10,1.14])
SEV_RESP = {"Low":300,"Medium":190,"High":110,"Critical":55}   # median response mins in 2020
SEV_FIN  = {"Low":1800,"Medium":9000,"High":48000,"Critical":260000}
CAT_FIN  = {"Phishing":.9,"Malware":1.0,"Ransomware":2.4,"DDoS":.8,"Insider Threat":1.5,"Web App Attack":1.1}

# ---------------- generate one batch of clean "ground truth" incidents ----------------
def generate(rng, years, n_year, months_avail, first_id):
    rows=[]; iid=1
    for y in years:
        t=(y-2020)/4; w=W20*(1-t)+W24*t; w/=w.sum()
        n=n_year[y]
        nm=months_avail.get(y,12)                       # year-to-date: only the first nm months exist
        mm=MONTH_MULT0.copy(); mm[nm:]=0; mm/=mm.sum()
        cats=rng.choice(len(CATS),n,p=w)
        months=rng.choice(12,n,p=mm)
        for c,m in zip(cats,months):
            cat=CATS[c]
            sub=rng.choice(SUBS[cat],p=SUBW[cat])
            sev=rng.choice(SEV,p=SEVW[cat])
            day=rng.integers(1,29)
            date=pd.Timestamp(y,m+1,int(day))
            country=rng.choice(COUNTRIES,p=CW)
            ind=rng.choice(INDS,p=IW)
            origin="Internal" if cat=="Insider Threat" else ("Internal" if rng.random()<.04 else "External")
            src=rng.choice(DSRC,p=DW)
            det=max(1,int(rng.lognormal(np.log(42*(1-.06*(y-2020))),.7)))
            resp=max(5,int(rng.lognormal(np.log(SEV_RESP[sev]*(1-.07*(y-2020))),.55)))
            # status: older years more resolved; recent months slightly less
            pm=0.80+0.018*(y-2020)
            if sev=="Critical": pm-=.03
            r=rng.random()
            if r<pm: st="Mitigated"
            elif r<pm+(1-pm)*.50: st="Contained"
            elif r<pm+(1-pm)*.85: st="Under Investigation"
            else: st="Open"
            systems=max(1,int(rng.lognormal(np.log(3 if sev in("Low","Medium") else 9),.8)))
            data_mb=round(float(rng.lognormal(np.log({"Low":4,"Medium":40,"High":320,"Critical":1800}[sev]),.9)),1) if cat in("Insider Threat","Ransomware","Web App Attack","Malware") else 0.0
            fin=round(float(rng.lognormal(np.log(SEV_FIN[sev]*CAT_FIN[cat]),.6)),2)
            rows.append([f"INC-{iid:05d}",date,cat,sub,sev,country,ind,origin,src,st,det,resp,systems,data_mb,fin,rng.choice(TEAMS)])
            iid+=1
    cols=["Incident_ID","Detected_Date","Threat_Category","Sub_Type","Severity","Source_Country","Target_Industry","Attack_Origin","Detection_Source","Status","Detection_Time_Min","Response_Time_Min","Affected_Systems","Data_Compromised_MB","Financial_Impact_USD","Analyst_Team"]
    truth=pd.DataFrame(rows,columns=cols).sort_values("Detected_Date").reset_index(drop=True)
    truth["Incident_ID"]=[f"INC-{first_id+i:05d}" for i in range(len(truth))]
    return truth

# ---------------- make the export deliberately messy (RAW) ----------------
def messify(rng, clean_truth):
    raw=clean_truth.copy()
    raw["Detected_Date"]=raw["Detected_Date"].dt.strftime("%Y-%m-%d")
    ix=rng.random(len(raw))<.20
    raw.loc[ix,"Detected_Date"]=pd.to_datetime(raw.loc[ix,"Detected_Date"]).dt.strftime("%d/%m/%Y")
    variants={"Phishing":["phishing","PHISHING"," Phishing","Phising"],"Malware":["malware","MALWARE","Malware "],
     "Ransomware":["ransomware","RANSOMWARE","Ransom-ware"],"DDoS":["ddos","DDOS","Ddos","DDoS "],
     "Insider Threat":["insider threat","Insider threat","INSIDER THREAT"],"Web App Attack":["web app attack","Web-App Attack","WEB APP ATTACK"]}
    for c,v in variants.items():
        m=(raw["Threat_Category"]==c)&(rng.random(len(raw))<.07)
        raw.loc[m,"Threat_Category"]=rng.choice(v,m.sum())
    fm=rng.random(len(raw))<.30
    raw["Financial_Impact_USD"]=raw["Financial_Impact_USD"].astype(object)
    raw.loc[fm,"Financial_Impact_USD"]=raw.loc[fm,"Financial_Impact_USD"].apply(lambda v:f"${v:,.2f}")
    raw.loc[rng.random(len(raw))<.015,"Severity"]=np.nan
    raw.loc[rng.random(len(raw))<.02,"Source_Country"]=np.nan
    raw.loc[rng.random(len(raw))<.01,"Target_Industry"]=np.nan
    neg=rng.random(len(raw))<.005; raw.loc[neg,"Response_Time_Min"]=-1
    out=(rng.random(len(raw))<.003)&~neg; raw.loc[out,"Response_Time_Min"]=99999
    raw.loc[rng.random(len(raw))<.01,"Detection_Source"]=raw["Detection_Source"].str.lower()
    dups=raw.sample(int(len(raw)*.015),random_state=3)
    raw=pd.concat([raw,dups]).sample(frac=1,random_state=5).reset_index(drop=True)
    return raw

if __name__=="__main__":
    parts=[]
    for seed,yrs,ny,ma,first in BATCHES:
        rng=np.random.default_rng(seed)
        truth=generate(rng,yrs,ny,ma,first)
        parts.append(messify(rng,truth))
    pd.concat(parts,ignore_index=True).to_csv("raw_threat_incidents.csv",index=False)

    # ---------------- CLEAN (the actual pipeline) ----------------
    df=pd.read_csv("raw_threat_incidents.csv",dtype=str)
    n0=len(df); log={"raw_rows":n0}
    df=df.drop_duplicates(); log["duplicates_removed"]=n0-len(df)
    def pdate(s):
        return pd.to_datetime(s,format="%Y-%m-%d",errors="coerce").fillna(pd.to_datetime(s,format="%d/%m/%Y",errors="coerce"))
    df["Detected_Date"]=pdate(df["Detected_Date"])
    log["bad_dates"]=int(df["Detected_Date"].isna().sum())
    canon={re.sub(r"[^a-z]","",c.lower()):c for c in CATS}; canon["phising"]="Phishing"; canon["ransomware"]="Ransomware"
    fix=df["Threat_Category"].str.lower().str.replace(r"[^a-z]","",regex=True).map(canon)
    log["category_labels_fixed"]=int((fix!=df["Threat_Category"]).sum()); df["Threat_Category"]=fix
    df["Detection_Source"]=df["Detection_Source"].str.strip().str.lower().map({s.lower():s for s in DSRC})
    assert df["Detection_Source"].notna().all()
    df["Financial_Impact_USD"]=df["Financial_Impact_USD"].str.replace(r"[$,]","",regex=True).astype(float)
    for c in ["Detection_Time_Min","Response_Time_Min","Affected_Systems","Data_Compromised_MB"]: df[c]=pd.to_numeric(df[c])
    bad=(df["Response_Time_Min"]<=0)|(df["Response_Time_Min"]>5000); log["bad_response_times"]=int(bad.sum())
    df["Severity"]=df["Severity"].fillna("Unknown")
    log["missing_severity"]=int((df["Severity"]=="Unknown").sum())
    df.loc[bad,"Response_Time_Min"]=np.nan
    # imputation medians are taken within the delivery batch (2020-24 vs 2025-26) so that adding a new
    # batch never restates the figures already published for earlier years
    df["_batch"]=(df["Incident_ID"].str[4:].astype(int)>=BATCHES[1][4]).astype(int)
    med=df.groupby(["_batch","Threat_Category","Severity"])["Response_Time_Min"].transform("median")
    bmed=df.groupby("_batch")["Response_Time_Min"].transform("median")
    df["Response_Time_Min"]=df["Response_Time_Min"].fillna(med).fillna(bmed).round().astype(int)
    df=df.drop(columns="_batch")
    log["missing_country"]=int(df["Source_Country"].isna().sum()); df["Source_Country"]=df["Source_Country"].fillna("Unknown")
    log["missing_industry"]=int(df["Target_Industry"].isna().sum()); df["Target_Industry"]=df["Target_Industry"].fillna("Unknown")
    # fill Unknown severity from sub-type-neutral mode within category
    mode=df[df.Severity!="Unknown"].groupby("Threat_Category")["Severity"].agg(lambda s:s.mode()[0])
    u=df["Severity"]=="Unknown"; df.loc[u,"Severity"]=df.loc[u,"Threat_Category"].map(mode)
    df=df.sort_values(["Detected_Date","Incident_ID"],kind="stable").reset_index(drop=True)
    df["Year"]=df["Detected_Date"].dt.year; df["Month"]=df["Detected_Date"].dt.month
    df["Month_Name"]=df["Detected_Date"].dt.strftime("%b")
    SLA={"Critical":60,"High":120,"Medium":240,"Low":480}
    df["SLA_Target_Min"]=df["Severity"].map(SLA); df["SLA_Met"]=np.where(df["Response_Time_Min"]<=df["SLA_Target_Min"],"Yes","No")
    df["Is_Mitigated"]=(df["Status"]=="Mitigated").astype(int)
    df["Detected_Date"]=df["Detected_Date"].dt.strftime("%Y-%m-%d")
    df.to_csv("processed_threat_incidents.csv",index=False)
    log["processed_rows"]=len(df); json.dump(log,open("clean_log.json","w"),indent=1); print(log)

    # ---------------- AGGREGATES for dashboard ----------------
    MN=["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]
    def agg(d):
        o={}
        o["total"]=int(len(d)); o["mitigated"]=int(d.Is_Mitigated.sum())
        o["rate"]=round(o["mitigated"]/max(1,o["total"])*100,1)
        o["nm"]=int(d.Month.nunique()) if d.Year.nunique()==1 else 12      # months with data (12 for full years)
        o["monthly"]=[int((d.Month==m).sum()) for m in range(1,13)]
        o["mttr"]=[round(float(d[d.Month==m].Response_Time_Min.mean())/60,2) if (d.Month==m).any() else 0 for m in range(1,13)]
        o["mttr_all"]=round(float(d.Response_Time_Min.mean())/60,2)
        o["mtt_detect"]=round(float(d.Detection_Time_Min.mean()),1)
        o["sev"]={s:int((d.Severity==s).sum()) for s in ["Critical","High","Medium","Low"]}
        o["cats"]=[]
        for c in CATS:
            dc=d[d.Threat_Category==c]
            o["cats"].append({"name":c,"n":int(len(dc)),"rate":round(float(dc.Is_Mitigated.mean()*100),1) if len(dc) else 0,
              "subs":[{"name":s,"n":int((dc.Sub_Type==s).sum())} for s in SUBS[c]],
              "crit":int((dc.Severity=="Critical").sum()),"fin":round(float(dc.Financial_Impact_USD.sum())/1e6,2)})
        o["countries"]=[{"name":c,"n":int((d.Source_Country==c).sum())} for c in COUNTRIES]
        o["industries"]=[{"name":c,"n":int((d.Target_Industry==c).sum())} for c in INDS]
        o["dsrc"]=[{"name":c,"n":int((d.Detection_Source==c).sum())} for c in DSRC]
        o["origin"]={"External":int((d.Attack_Origin=="External").sum()),"Internal":int((d.Attack_Origin=="Internal").sum())}
        o["funnel"]=[int(len(d)),int((d.Status!="Open").sum()),int(d.Status.isin(["Contained","Mitigated"]).sum()),int((d.Status=="Mitigated").sum())]
        o["status"]={s:[int(((d.Month==m)&(d.Status==s)).sum()) for m in range(1,13)] for s in ["Mitigated","Contained","Under Investigation","Open"]}
        o["sla"]=round(float((d.SLA_Met=="Yes").mean()*100),1)
        o["fin"]=round(float(d.Financial_Impact_USD.sum())/1e6,2)
        o["sevstatus"]={s:{t:int(((d.Severity==s)&(d.Status==t)).sum()) for t in ["Mitigated","Contained","Under Investigation","Open"]} for s in ["Critical","High","Medium","Low"]}
        return o
    data={str(y):agg(df[df.Year==y]) for y in YEARS}; data["All"]=agg(df)
    meta={"months":MN,"target":90,"partial":{"2026":"Jan-Sep 2026 (year to date)"},"countries_geo":{"China":[35,105],"Russia":[60,100],"United States":[38,-97],"India":[21,78],"Brazil":[-10,-52],"Iran":[32,53],"North Korea":[40,127],"Ukraine":[49,32],"Germany":[51,10],"Nigeria":[9,8],"Vietnam":[16,108],"Turkey":[39,35]}}
    json.dump({"data":data,"meta":meta},open("agg.json","w"))
    print({y:(data[y]['total'],data[y]['rate'],data[y]['mttr_all']) for y in data})
    print(data["2021"]["cats"][0], data["All"]["origin"])
