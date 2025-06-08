#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
DIGITAL BRAIN – versione ULTRA
────────────────────────────────────────────────────────────────────────────
USO IN AMBIENTE DI TEST!  Ogni modifica critica chiede la conferma manuale.
────────────────────────────────────────────────────────────────────────────
"""

# ───────────────────────────── IMPORT  BASE ──────────────────────────────
import os, re, json, sqlite3, threading, time, sched, inspect, textwrap
from datetime import datetime
from functools import wraps
from time import sleep as sched_sleep

# HTTP
import requests

# Speech Recognition
import speech_recognition as sr

# Flask stack
from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, jsonify)
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

# OpenAI / Agents SDK (mock Runner incl.)
from openai import OpenAI
class Agent:
    def __init__(self, name, instructions): self.name, self.instructions = name, instructions
class Runner:
    @staticmethod
    def run_sync(agent, prompt):
        #  ‼️  Sostituisci con chiamata reale al tuo framework di agent se lo possiedi.
        class Result: final_output = f"[FAKE PATCH] {prompt[:60]}..."
        return Result()

# ─────────────────────── CARICAMENTO VARIABILI ENV ───────────────────────
load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY") or exit("❌  OPENAI_API_KEY mancante")
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY") or exit("❌  FLASK_SECRET_KEY mancante")
client = OpenAI(api_key=OPENAI_API_KEY)

# ─────────────────────────── CONFIG  APP  FLASK ──────────────────────────
app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY
BASE_DIR = os.path.abspath(os.path.dirname(__file__))  # cartella progetto

# ───────────────────────────── DATABASE  INIT ────────────────────────────
def init_db():
    with sqlite3.connect("assistant_memory.db") as db:
        c = db.cursor()
        # Conversazioni
        c.execute("""CREATE TABLE IF NOT EXISTS conversazioni(
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT,
            username TEXT, richiesta TEXT, risposta TEXT,
            event_date TEXT, tag TEXT)""")
        # Utenti
        c.execute("""CREATE TABLE IF NOT EXISTS technicians(
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE,
            password TEXT, fullname TEXT, role TEXT DEFAULT 'user')""")
        # Promemoria
        c.execute("""CREATE TABLE IF NOT EXISTS reminders(
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT,
            reminder_text TEXT, remind_date TEXT, delivered INTEGER DEFAULT 0)""")
        # Credenziali
        c.execute("""CREATE TABLE IF NOT EXISTS credentials(
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT,
            device TEXT, user_val TEXT, email TEXT, password TEXT,
            timestamp TEXT)""")
        # Parametri tecnici
        c.execute("""CREATE TABLE IF NOT EXISTS parameters(
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT,
            device TEXT, info TEXT, timestamp TEXT)""")
        # Posizioni
        c.execute("""CREATE TABLE IF NOT EXISTS positions(
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT,
            person TEXT, link TEXT, timestamp TEXT)""")
        # Conoscenza estratta
        c.execute("""CREATE TABLE IF NOT EXISTS knowledge(
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT,
            topic TEXT, details TEXT, timestamp TEXT)""")
        # Utenti di default
        if c.execute("SELECT COUNT(*) FROM technicians").fetchone()[0] == 0:
            c.executemany("""INSERT INTO technicians(username,password,fullname,role)
                             VALUES(?,?,?,?)""",
                          [("tech",  generate_password_hash("password"),
                            "Tecnico Default","user"),
                           ("admin", generate_password_hash("svolta2025"),
                            "Amministratore","admin")])
        db.commit()

# ───────────────────────────── FILTRI JINJA ──────────────────────────────
@app.template_filter("startswith")
def jinja_startswith(value, prefix): return isinstance(value,str) and value.startswith(prefix)

# ─────────────────────  DECORATORE  ADMIN REQUIRED  ──────────────────────
def admin_required(fn):
    @wraps(fn)
    def _wrap(*a, **kw):
        if "user" not in session or session["user"].get("role")!="admin":
            flash("Solo admin permessi", "danger"); return redirect(url_for("index"))
        return fn(*a, **kw)
    return _wrap

# ─────────────────────── FUNZIONI UTILITY  MESSAGGI ───────────────────────
def clean_message(msg:str)->str: return msg.strip()

def adheres_to_usage_instructions(msg:str)->bool:
    kws = ["leggi file:","scrivi file:","modifica file:","aggiungi file:",
           "elimina file:","crea cartella:","esplora cartella:","computer:"]
    return any(k in msg.lower() for k in kws)

def get_tags(msg:str)->str|None:
    tags=[t for t in["attivazione","errore","configurazione","installazione","manutenzione"]
          if t in msg.lower()]
    return ", ".join(tags) if tags else None

# ─────────────────────────  FILE-SYSTEM  API  ────────────────────────────
def crea_file(path,txt): os.makedirs(os.path.dirname(path),exist_ok=True); open(path,'w',encoding='utf-8').write(txt); return f"Creato {path}"
def leggi_file(p): return open(p,'r',encoding='utf-8').read() if os.path.exists(p) else f"File {p} inesistente."
def scrivi_file(p,txt): open(p,'w',encoding='utf-8').write(txt); return f"Scritto {p}"
def aggiungi_file(p,txt): open(p,'a',encoding='utf-8').write(txt); return f"Aggiunto a {p}"
def elimina_file(p): os.remove(p); return f"Eliminato {p}"
def crea_cartella(p): os.makedirs(p,exist_ok=True); return f"Cartella {p} ok"
def esplora_cartella(p): return "\n".join(os.listdir(p)) if os.path.exists(p) else "Cartella non esiste"

def processa_comando_file(msg:str):
    m=msg.lower()
    try:
        if m.startswith("leggi file:"): return leggi_file(msg[10:].strip())
        if m.startswith(("scrivi file:","modifica file:")):
            _,resto=msg.split("file:",1)
            if "::" not in resto: return "Sintassi: scrivi file:<percorso>::<contenuto>"
            p,txt=[x.strip() for x in resto.split("::",1)]
            return scrivi_file(p,txt)
        if m.startswith("aggiungi file:"):
            _,resto=msg.split("aggiungi file:",1)
            if "::" not in resto: return "Sintassi corretta: aggiungi file:<percorso>::<contenuto>"
            p,txt=[x.strip() for x in resto.split("::",1)]; return aggiungi_file(p,txt)
        if m.startswith("elimina file:"): return elimina_file(msg[13:].strip())
        if m.startswith("crea cartella:"): return crea_cartella(msg[14:].strip())
        if m.startswith("esplora cartella:"): return esplora_cartella(msg[17:].strip())
    except Exception as e:
        return f"Errore comando file: {e}"
    return None

# ─────────────────────── POSIZIONI (MAP LINKS)  DB ───────────────────────
def salva_posizione(user,person,link):
    with sqlite3.connect("assistant_memory.db") as db:
        db.execute("""INSERT INTO positions(username,person,link,timestamp)
                      VALUES(?,?,?,?)""",(user,person,link,datetime.now().isoformat()))
        db.commit()
def get_posizione(user,person):
    with sqlite3.connect("assistant_memory.db") as db:
        cur=db.execute("""SELECT link,timestamp FROM positions
                          WHERE username=? AND person LIKE ? ORDER BY id DESC""",
                       (user,f"%{person}%")); return cur.fetchone()

# ────────────────────────  OPENAI CHAT HELPER  ───────────────────────────
def generate_ai_response(user_msg, history, user_info):
    sys = ("Sei un assistente esperto di impianti elettrici e sistemi autonomi. "
           "Se il comando è avanzato o non riconosciuto, restituisci JSON {action,filepath,content}. "
           "Per comandi 'computer:' chiedi conferma prima di procedere.")
    messages=[{"role":"system","content":sys},
              {"role":"user","content":history},
              {"role":"user","content":user_msg}]
    try:
        r=client.chat.completions.create(model="gpt-4o-mini",messages=messages,
                                         temperature=0.0,max_tokens=300)
        return r.choices[0].message.content.strip()
    except Exception as e:
        print("OpenAI err:",e); return "Errore OpenAI."

def process_ai_command(resp:str):
    try:
        cmd=json.loads(resp); a,f,c=cmd.get("action"),cmd.get("filepath"),cmd.get("content","")
        if not f: return "JSON senza filepath."
        return {"update":scrivi_file,"append":aggiungi_file,
                "delete":elimina_file,"create":crea_file}.get(a,lambda *_:"Azione sconosciuta")(f,c)
    except Exception: return resp

# ────────────────────────  SPECIAL COMMANDS  REGEX  ──────────────────────
def processa_comando_speciale(msg:str):
    u=session["user"]["username"] if "user" in session else "anon"

    # PROMEMORIA
    m=re.search(r"^(ricordami|annotami|segna|memorizza)\s+(.*?)\s+(il|per il|del)\s+giorno\s+([\d\/\-]+)",msg,re.I)
    if m:
        testo, data_str = m.group(2).strip(), m.group(4).strip()
        try: dt=datetime.strptime(data_str.replace("-","/"),"%d/%m/%Y").strftime("%Y-%m-%d")
        except: return "Data non valida."
        salva_promemoria(u,testo,dt); return f"Promemoria salvato per {dt}: {testo}"

    # CREDENZIALI Salva
    m=re.search(r"salva(?:mi)?\s+credenziali(?:\s+di\s+)?([\w\s]+)[\:\-]\s*user\w*\s*:\s*([^,]+),?\s*(?:email|mail)?\s*:\s*([^,]+)?,\s*(?:pwd|password)\s*:\s*(.+)",msg,re.I)
    if m:
        ref,userv,mail,pwd=(m.group(1),m.group(2),m.group(3) or "non fornita",m.group(4))
        salva_credenziali(u,ref.strip(),userv.strip(),mail.strip(),pwd.strip())
        return f"Credenziali {ref} salvate."

    # CREDENZIALI View
    m=re.search(r"(dammi|mostrami|visualizza|inviami)\s+credenziali\s+(di|per)\s+([\w\s]+)",msg,re.I)
    if m:
        ref=m.group(3).strip(); rec=get_credenziali(u,ref)
        return ("Nessuna credenziale trovata." if not rec else
                "\n".join([f"{d}| user:{u_}| email:{e}| pwd:{p}" for d,u_,e,p,_ in rec]))

    # PARAM Salva
    m=re.search(r"(salva|memorizza|annota)\s+parametri\s+(di|per)\s+([\w\s]+)[\:\-]\s*(.+)",msg,re.I)
    if m:
        dev,info=m.group(3).strip(),m.group(4).strip(); salva_parametri_func(u,dev,info)
        return f"Parametri {dev} salvati."

    # PARAM View
    m=re.search(r"(dammi|mostrami|visualizza)\s+(parametri|dati|info)\s+(di|per)\s+([\w\s]+)",msg,re.I)
    if m:
        dev=m.group(4).strip(); rec=get_parametri(u,dev)
        return "Nessun parametro" if not rec else "\n".join([f"{d}| {i}" for d,i,_ in rec])

    # POSIZIONE salva
    m=re.search(r"salvami la posizione di\s+([\w\s]+)\s*(https?://\S+)",msg,re.I)
    if m:
        salva_posizione(u,m.group(1).strip(),m.group(2).strip()); return "Posizione salvata."

    # POSIZIONE visualizza
    m=re.search(r"dammi la posizione di\s+([\w\s]+)",msg,re.I)
    if m:
        rec=get_posizione(u,m.group(1).strip())
        return "Nessuna posizione." if not rec else f"{rec[0]} (salvata {rec[1]})"

    # SALVA MEMORIA
    if re.search(r"^(salva memoria|memorizza conversazioni|archivia chat)",msg,re.I):
        with sqlite3.connect("assistant_memory.db") as db:
            cur=db.execute("""SELECT timestamp,richiesta,risposta FROM conversazioni
                              WHERE username=? ORDER BY id""",(u,))
            txt="\n".join([f"{t}: TU {r} | AI {res}" for t,r,res in cur.fetchall()])
        fn=f"memorie/mem_{u}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        os.makedirs("memorie",exist_ok=True); open(fn,'w',encoding='utf-8').write(txt)
        return f"Memoria salvata in {fn}"

    # RICERCA ERRORI
    m=re.search(r"(cerca|trova)\s+errore:\s+(.+)",msg,re.I)
    if m:
        kw=m.group(2)
        with sqlite3.connect("assistant_memory.db") as db:
            cur=db.execute("""SELECT timestamp,richiesta,risposta FROM conversazioni
                              WHERE (richiesta LIKE ? OR risposta LIKE ?) AND username=?""",
                           (f"%{kw}%","%"+kw+"%",u))
            rs=cur.fetchall()
        return "Nessun risultato" if not rs else "\n".join([f"{t}: {rq} -> {rp}" for t,rq,rp in rs])

    # RIASSUNTO GIORNATA
    if re.search(r"riassumimi la giornata",msg,re.I):
        today=datetime.now().strftime("%Y-%m-%d")
        with sqlite3.connect("assistant_memory.db") as db:
            cur=db.execute("""SELECT richiesta,risposta FROM conversazioni WHERE username=? AND event_date=?""",
                           (u,today)); rs=cur.fetchall()
        return "Niente oggi" if not rs else "\n".join([f"- {q} => {r}" for q,r in rs])

    return None

# ───────────────────────────── DB HELPERS  ────────────────────────────────
def salva_interazione(user,q,a,dt=None,tag=None):
    with sqlite3.connect("assistant_memory.db") as db:
        db.execute("""INSERT INTO conversazioni(timestamp,username,richiesta,risposta,event_date,tag)
                      VALUES(?,?,?,?,?,?)""",
                   (datetime.now().isoformat(),user,q,a,dt,tag)); db.commit()

def salva_promemoria(user,txt,date): with sqlite3.connect("assistant_memory.db") as db: db.execute(
    "INSERT INTO reminders(username,reminder_text,remind_date)VALUES(?,?,?)",(user,txt,date)); db.commit()

def salva_credenziali(user,ref,uv,mail,pwd):
    with sqlite3.connect("assistant_memory.db") as db:
        db.execute("""INSERT INTO credentials(username,device,user_val,email,password,timestamp)
                      VALUES(?,?,?,?,?,?)""",
                   (user,ref,uv,mail,pwd,datetime.now().isoformat())); db.commit()

def get_credenziali(user,ref=None):
    with sqlite3.connect("assistant_memory.db") as db:
        cur=db.execute("""SELECT device,user_val,email,password,timestamp FROM credentials
                          WHERE username=? AND device LIKE ? ORDER BY id DESC""",
                       (user,f"%{ref or ''}%")); return cur.fetchall()

def salva_parametri_func(user,dev,info):
    with sqlite3.connect("assistant_memory.db") as db:
        db.execute("""INSERT INTO parameters(username,device,info,timestamp)
                      VALUES(?,?,?,?)""",(user,dev,info,datetime.now().isoformat())); db.commit()

def get_parametri(user,dev=None):
    with sqlite3.connect("assistant_memory.db") as db:
        cur=db.execute("""SELECT device,info,timestamp FROM parameters
                          WHERE username=? AND device LIKE ? ORDER BY id DESC""",
                       (user,f"%{dev or ''}%")); return cur.fetchall()

def check_reminders(user):
    now=datetime.now()
    due=[]
    with sqlite3.connect("assistant_memory.db") as db:
        cur=db.execute("SELECT id,reminder_text,remind_date FROM reminders WHERE username=? AND delivered=0",(user,))
        for rid,txt,dt in cur.fetchall():
            try: rdate=datetime.strptime(dt,"%Y-%m-%d")
            except: rdate=now
            if now.date()>=rdate.date():
                due.append((rid,txt,dt))
                db.execute("UPDATE reminders SET delivered=1 WHERE id=?",(rid,))
        db.commit()
    return due

def learn_from_interaction(user,conversation):
    agent=Agent("Learner","Estrai conoscenza utile.")
    out=Runner.run_sync(agent,conversation).final_output
    if out.lower()!="nessuna conoscenza rilevata":
        with sqlite3.connect("assistant_memory.db") as db:
            db.execute("""INSERT INTO knowledge(username,topic,details,timestamp)
                          VALUES(?,?,?,?)""",(user,"Conversazione",out,datetime.now().isoformat()))
            db.commit()
    return out

# ─────────────────────────── SYSTEM OPTIMIZER ────────────────────────────
class SystemOptimizer:
    def __init__(self,check_interval=3600): self.intv=check_interval
    def check_system_status(self):
        if os.path.exists("error.log") and "conversazioni" in open("error.log","r",encoding='utf-8').read():
            return "no such table: conversazioni"
    def generate_patch(self,issue):
        agent=Agent("Optimizer","Genera patch Python per app Flask/SQLite.")
        return Runner.run_sync(agent,issue).final_output
    def apply_patch(self,code):
        open("auto_patch.py","w",encoding='utf-8').write(code)
        print("Patch salvata in auto_patch.py")
    def optimize(self):
        issue=self.check_system_status()
        if issue: self.apply_patch(self.generate_patch(issue))
    def run(self):
        while True: self.optimize(); sched_sleep(self.intv)

# ────────────────────────── ANALISI  DEL CODICE ──────────────────────────
def analizza_codice_progetto():
    """Legge tutti i .py del progetto, invia all'AI un prompt e ritorna una patch se necessario."""
    report=[]
    for root,_,files in os.walk(BASE_DIR):
        for f in files:
            if f.endswith(".py") and f!="auto_patch.py":
                path=os.path.join(root,f)
                code=open(path,'r',encoding='utf-8').read()
                if len(code)>5000: code=code[:5000]  # taglia context
                report.append(f"\n### File: {path}\n{code}")
    big_prompt=("Analizza i seguenti file python, trova bug o ottimizzazioni e genera patch JSON "
                "con chiavi: filepath, action(update|append|create|delete), content.\n"
                +"\n".join(report))
    agent=Agent("CodeReviewer","Se trovi miglioramenti, ritorna lista JSON di patch.")
    patches_json=Runner.run_sync(agent,big_prompt).final_output
    try: patches=json.loads(patches_json)
    except Exception: patches=[]
    applied=[]
    for p in patches:
        action,fp,ct=p["action"],p["filepath"],p.get("content","")
        applied.append(process_ai_command(json.dumps(p)))
    return applied

# ─────────────────────────  INPUT  VOCALE  ROUTE ─────────────────────────
@app.route("/ascolta")
def route_ascolta(): return jsonify({"risultato":ascolta_microfono() or ""})

# ─────────────────────────  PLAYWRIGHT COMPUTER USE ──────────────────────
def esegui_comando_computer(cmd):
    try: from playwright.sync_api import sync_playwright
    except: return "Playwright mancante."
    if input("Eseguo comando browser? S/N ").lower()!="s": return "Annullato."
    with sync_playwright() as p:
        br=p.chromium.launch(headless=False); pg=br.new_page()
        url=re.search(r"(https?://\S+)",cmd); url=url.group(0) if url else "https://www.bing.com"
        pg.goto(url); pg.wait_for_timeout(5000); br.close(); return f"Aperto {url}"

# ────────────────────── THREAD PENSIERO CONTINUO REALE ────────────────────
def pensiero_continuo():
    while True:
        sugg="Ottimizzare cache grafica; generare patch?"
        print("💡 Suggerimento:",sugg)
        if input("Applico? S/N ").lower()=="s":
            patch=optimizer.generate_patch("Richiesta di miglioramento:\n"+sugg)
            optimizer.apply_patch(patch)
        time.sleep(600)
def start_pensiero(): threading.Thread(target=pensiero_continuo,daemon=True).start()

# ──────────────────────── THREAD OPTIMIZER BG ────────────────────────────
optimizer=SystemOptimizer()
threading.Thread(target=optimizer.run,daemon=True).start()

# ─────────────────────────────  FLASK ROUTES  ────────────────────────────
@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        u,p=request.form["username"],request.form["password"]
        with sqlite3.connect("assistant_memory.db") as db:
            cur=db.execute("SELECT username,password,fullname,role FROM technicians WHERE username=?",(u,))
            user=cur.fetchone()
        if user and check_password_hash(user[1],p):
            session["user"]={"username":u,"fullname":user[2],"role":user[3]}
            return redirect(url_for("index"))
        flash("Credenziali errate","danger")
    return render_template("login.html")

@app.route("/register",methods=["GET","POST"])
def register():
    if request.method=="POST":
        u,p,f=request.form["username"],request.form["password"],request.form["fullname"]
        try:
            with sqlite3.connect("assistant_memory.db") as db:
                db.execute("INSERT INTO technicians(username,password,fullname)VALUES(?,?,?)",
                           (u,generate_password_hash(p),f)); db.commit()
            flash("Registrato!","success"); return redirect(url_for("login"))
        except sqlite3.IntegrityError: flash("Username esistente","danger")
    return render_template("register.html")

@app.route("/logout");   def logout(): session.clear(); return redirect(url_for("login"))

@app.route("/check_reminders")
def chk_rem(): return jsonify({"reminders":[{"text":t,"dt":d} for _,t,d in check_reminders(session["user"]["username"]) ]})

@app.route("/learn",methods=["POST"])
def learn():
    u=session["user"]["username"]
    with sqlite3.connect("assistant_memory.db") as db:
        conv="\n".join([f"U:{r} | A:{a}" for r,a in db.execute(
            "SELECT richiesta,risposta FROM conversazioni WHERE username=? ORDER BY id DESC LIMIT 5",(u,))])
    flash("Apprendimento:"+learn_from_interaction(u,conv),"info"); return redirect(url_for("index"))

@app.route("/send",methods=["POST"])
def send():
    if "user" not in session: return redirect(url_for("login"))
    q=clean_message(request.form["message"]); u=session["user"]["username"]
    tag=get_tags(q); event_date=None
    m=re.search(r"il giorno (\d{1,2}[\/\-]\d{1,2}[\/\-]\d{4})",q,re.I)
    if m: event_date=datetime.strptime(m.group(1).replace("-","/"),"%d/%m/%Y").strftime("%Y-%m-%d")
    if q.lower().startswith("computer:"): a=esegui_comando_computer(q[9:])
    else:
        cmd=processa_comando_speciale(q) or processa_comando_file(q)
        if cmd: a=cmd
        else:
            with sqlite3.connect("assistant_memory.db") as db:
                hist="\n".join([f"Tu:{r}\nAI:{a}" for r,a in db.execute(
                    "SELECT richiesta,risposta FROM conversazioni WHERE username=? ORDER BY id DESC LIMIT 3",(u,))])
            a=process_ai_command(generate_ai_response(q,hist,session["user"]))
    salva_interazione(u,q,a,event_date,tag); return redirect(url_for("index"))

@app.route("/upload",methods=["POST"])
def upload():
    f=request.files.get("photo"); u=session["user"]["username"]
    if not f or f.filename=="": flash("Nessun file","danger"); return redirect(url_for("index"))
    os.makedirs("static/reports",exist_ok=True)
    fn=f"static/reports/rep_{datetime.now().strftime('%Y%m%d%H%M%S')}_{f.filename}"
    f.save(fn); flash("Foto caricata","success"); salva_interazione(u,"upload",f"Salvato {fn}")
    return redirect(url_for("index"))

@app.route("/create_reminder",methods=["POST"])
def create_rem():
    d,txt=request.form["date"],request.form["reminder_text"]; u=session["user"]["username"]
    salva_promemoria(u,txt,d); salva_interazione(u,f"crea promemoria {d}",txt,d)
    return redirect(url_for("index"))

@app.route("/")
def index():
    if "user" not in session: return redirect(url_for("login"))
    u=session["user"]["username"]; is_admin=session["user"]["role"]=="admin"
    conv=list(sqlite3.connect("assistant_memory.db").execute(
        "SELECT timestamp,username,richiesta,risposta,event_date,tag FROM conversazioni WHERE username=?",(u,)))
    return render_template("index.html",conversazioni=conv,user=session["user"],is_admin=is_admin)

# ──────────────────────────── AVVIO SERVER ───────────────────────────────
if __name__ == "__main__":
    init_db()
    start_pensiero()                    # avvia pensiero continuo reale
    app.run(debug=True,port=5000)