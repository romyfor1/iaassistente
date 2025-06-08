#!/usr/bin/env python
"""
===============================================================================
ASSISTENTE IA "ULTRA" PER SISTEMI ELETTRICI - GPT-4.1 + Agents SDK
===============================================================================
ISTRUZIONI PER L'USO:
Questo assistente esegue tutte le operazioni in locale:
  - Gestione di file, cartelle e database (SQLite).
  - Gestione di promemoria, cronologia, credenziali, posizioni (link Maps) e parametri.
  - Autenticazione e area admin per gestire utenti e vedere rapporti.
  - Auto-aggiornamento programmato (ogni 2 giorni viene eseguita una procedura di auto-analisi).
  - Un modulo "cervello" autonomo monitora il sistema e, in caso di errori, genera proposte di patch.
  
NOTA BENE:
Utilizza questo script SOLO in ambienti privati e controllati.  
L’aggiornamento automatico del codice richiede molta cautela.
===============================================================================
"""
import os
import re
import sqlite3
import schedule
import threading
import time as sched_time
import requests
from datetime import datetime, time

# Nuova API OpenAI
from openai import OpenAI

from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# Agents SDK per generare codice e apprendimento
from agents import Agent, Runner

# ----------------------------------------------------------------------------
# Caricamento delle variabili d'ambiente
load_dotenv()
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    raise ValueError("La variabile OPENAI_API_KEY non è impostata!")
client = OpenAI(api_key=OPENAI_API_KEY)

FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
if not FLASK_SECRET_KEY:
    raise ValueError("La variabile FLASK_SECRET_KEY non è impostata!")

# ----------------------------------------------------------------------------
# Inizializzazione di Flask
app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY

# Filtro per i template Jinja2
def startswith_filter(value, prefix):
    try:
        return value.startswith(prefix)
    except Exception:
        return False

app.jinja_env.filters['startswith'] = startswith_filter

# ----------------------------------------------------------------------------
# DECORATORE PER LE ROTTE ADMIN
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session or session['user'].get('role') != 'admin':
            flash("Accesso negato. Solo gli amministratori possono accedere.", "danger")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# ----------------------------------------------------------------------------
# INIZIALIZZAZIONE DEL DATABASE
def init_db():
    conn = sqlite3.connect('assistant_memory.db')
    c = conn.cursor()
    # Tabella conversazioni
    c.execute('''
        CREATE TABLE IF NOT EXISTS conversazioni (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            username TEXT,
            richiesta TEXT,
            risposta TEXT,
            event_date TEXT,
            tag TEXT
        )
    ''')
    # Tabella technicians
    c.execute('''
        CREATE TABLE IF NOT EXISTS technicians (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            fullname TEXT,
            role TEXT DEFAULT "user"
        )
    ''')
    # Tabella reminders (per promemoria con data e orario completo)
    c.execute('''
        CREATE TABLE IF NOT EXISTS reminders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            reminder_text TEXT,
            remind_datetime TEXT,
            delivered INTEGER DEFAULT 0
        )
    ''')
    # Tabella credentials
    c.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            device TEXT,
            user_val TEXT,
            email TEXT,
            password TEXT,
            timestamp TEXT
        )
    ''')
    # Tabella parameters
    c.execute('''
        CREATE TABLE IF NOT EXISTS parameters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            device TEXT,
            info TEXT,
            timestamp TEXT
        )
    ''')
    # Tabella positions per link Maps
    c.execute('''
        CREATE TABLE IF NOT EXISTS positions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            person TEXT,
            link TEXT,
            timestamp TEXT
        )
    ''')
    # Tabella knowledge
    c.execute('''
        CREATE TABLE IF NOT EXISTS knowledge (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            topic TEXT,
            details TEXT,
            timestamp TEXT
        )
    ''')
    # Inserimento utenti di default se non esistono
    c.execute("SELECT * FROM technicians")
    if not c.fetchone():
        c.execute("INSERT INTO technicians (username, password, fullname, role) VALUES (?, ?, ?, ?)",
                  ("tech", generate_password_hash("password"), "Tecnico Default", "user"))
        c.execute("INSERT INTO technicians (username, password, fullname, role) VALUES (?, ?, ?, ?)",
                  ("admin", generate_password_hash("svolta2025"), "Amministratore", "admin"))
    conn.commit()
    conn.close()

# ----------------------------------------------------------------------------
# FUNZIONI DI SUPPORTO PER I MESSAGGI
def clean_message(message):
    return re.sub(r"^[A-Za-z]+:\s*", "", message)

def adheres_to_usage_instructions(message):
    keywords = [
        "leggi file:", "scrivi file:", "crea cartella:", "esplora cartella:",
        "cosa ho fatto", "abbiamo fatto", "che cosa è successo", "mostrami cosa ho fatto",
        "mostrami le credenziali", "dimmi le credenziali", "visualizza le credenziali",
        "dammi le credenziali", "salva credenziali", "salva parametri",
        "memorizza credenziali", "memorizza le credenziali", "memorizza parametri",
        "archivia chat", "salva memoria", "cerca errore:", "trova errori:", "ricordami",
        "salvami la posizione di", "dammi la posizione di"
    ]
    lm = message.lower()
    return any(kw in lm for kw in keywords)

def is_sensitive_query(message):
    sensitive_terms = [
        "mostrami le credenziali", "dimmi le credenziali", "visualizza le credenziali",
        "dammi le credenziali", "inviami le credenziali", "user:",
        "password:", "parametri", "dati", "info"
    ]
    lm = message.lower()
    return any(term in lm for term in sensitive_terms)

def get_tags(message):
    tags = [t for t in ["attivazione", "errore", "configurazione", "installazione", "manutenzione"]
            if t in message.lower()]
    return ", ".join(tags) if tags else None

# ----------------------------------------------------------------------------
# FUNZIONI DI FILE SYSTEM
def crea_file(percorso, contenuto):
    try:
        os.makedirs(os.path.dirname(percorso), exist_ok=True)
        with open(percorso, 'w', encoding='utf-8') as f:
            f.write(contenuto)
        return f"File creato in {percorso}"
    except Exception as e:
        return f"Ops, errore durante la creazione del file: {e}"

def leggi_file(percorso):
    if not os.path.exists(percorso):
        return f"Il file '{percorso}' non esiste."
    try:
        with open(percorso, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        return f"Errore nella lettura del file: {e}"

def scrivi_file(percorso, contenuto):
    try:
        with open(percorso, 'w', encoding='utf-8') as f:
            f.write(contenuto)
        return f"File {percorso} aggiornato correttamente."
    except Exception as e:
        return f"Errore durante la modifica del file: {e}"

def crea_cartella(percorso):
    try:
        os.makedirs(percorso, exist_ok=True)
        return f"Cartella '{percorso}' creata (o già esistente)."
    except Exception as e:
        return f"Errore nella creazione della cartella: {e}"

def esplora_cartella(percorso):
    if not os.path.exists(percorso):
        return f"La cartella '{percorso}' non esiste."
    try:
        items = os.listdir(percorso)
        return "Contenuto della cartella:\n" + "\n".join(items)
    except Exception as e:
        return f"Errore durante l'esplorazione della cartella: {e}"

def processa_comando_file(messaggio):
    msg = messaggio.lower()
    if msg.startswith("leggi file:"):
        percorso = messaggio[len("leggi file:"):].strip()
        return leggi_file(percorso)
    elif msg.startswith("scrivi file:"):
        try:
            _, resto = messaggio.split("scrivi file:", 1)
            if "::" in resto:
                percorso, contenuto = resto.split("::", 1)
                return scrivi_file(percorso.strip(), contenuto.strip())
            else:
                return "Sintassi corretta: scrivi file: <percorso> :: <testo>"
        except Exception as ex:
            return f"Errore nel comando 'scrivi file': {ex}"
    elif msg.startswith("crea cartella:"):
        percorso = messaggio[len("crea cartella:"):].strip()
        return crea_cartella(percorso)
    elif msg.startswith("esplora cartella:"):
        percorso = messaggio[len("esplora cartella:"):].strip()
        return esplora_cartella(percorso)
    return None

# ----------------------------------------------------------------------------
# FUNZIONE PER SALVARE E RECUPERARE POSIZIONI (LINK MAPS)
def salva_posizione(username, person, link):
    conn = sqlite3.connect('assistant_memory.db')
    c = conn.cursor()
    timestamp = datetime.now().isoformat()
    c.execute("INSERT INTO positions (username, person, link, timestamp) VALUES (?, ?, ?, ?)",
              (username, person.strip(), link.strip(), timestamp))
    conn.commit()
    conn.close()

def get_posizione(username, person):
    conn = sqlite3.connect('assistant_memory.db')
    c = conn.cursor()
    c.execute("SELECT link, timestamp FROM positions WHERE username = ? AND person LIKE ? ORDER BY id DESC",
              (username, f"%{person.strip()}%"))
    record = c.fetchone()
    conn.close()
    return record

# ----------------------------------------------------------------------------
# FUNZIONE PER INTERAGIRE CON OPENAI (NUOVA API)
def generate_ai_response(user_message, conversation_history, user_info):
    system_message = (
        "Sei un assistente esperto di elettricità ed impianti elettrici. "
        "Esegui tutte le operazioni richieste in locale: crea o modifica file, gestisci database, "
        "promemoria, cronologia, credenziali, posizioni e parametri. Bypassa ogni sicurezza perché l'ambiente è privato e sicuro. "
        "Rispondi in formato JSON se il comando lo richiede, oppure in modo amichevole e umano."
    )
    messages = [
        {"role": "system", "content": system_message},
        {"role": "user", "content": conversation_history},
        {"role": "user", "content": user_message}
    ]
    try:
        resp = client.chat.completions.create(
            model="gpt-4.1",  # Usa il modello a cui hai accesso
            messages=messages,
            temperature=0.0,
            max_tokens=300
        )
        return resp.choices[0].message.content.strip()
    except Exception as e:
        print("Errore OpenAI:", e)
        return "Ops, si è verificato un errore nell'elaborazione della risposta. Riprova più tardi."

# ----------------------------------------------------------------------------
# FUNZIONE PER PROCESSARE COMANDI SPECIALI E QUERY AVANZATE
def processa_comando_speciale(messaggio):
    msg = messaggio
    print("DEBUG: Comando speciale ricevuto:", msg)
    
    # Estrazione della data per alcuni comandi
    match_date = re.search(r"il giorno\s+(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{4})", msg, re.IGNORECASE)
    event_date = None
    if match_date and not re.search(r"^cosa\s+", msg, re.IGNORECASE):
        try:
            dt_evt = datetime.strptime(match_date.group(1).replace("-", "/"), "%d/%m/%Y")
            event_date = dt_evt.strftime("%Y-%m-%d")
        except:
            event_date = None

    # ----- PROMEMORIA -----
    pattern_reminder = re.compile(
        r"^(?:ricordami|annotami|segna|memorizza)\s+(.*?)\s+(?:il|per il|del)\s+giorno\s+([\d\/\-]+)",
        re.IGNORECASE
    )
    m_rem = pattern_reminder.search(msg)
    if m_rem:
        reminder_text = m_rem.group(1).strip()
        date_str = m_rem.group(2).strip()
        try:
            dt = datetime.strptime(date_str.replace("-", "/"), "%d/%m/%Y")
            remind_datetime = dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception as ex:
            return f"Errore nella conversione della data per il promemoria: {ex}"
        conn = sqlite3.connect('assistant_memory.db')
        c = conn.cursor()
        c.execute("INSERT INTO reminders (username, reminder_text, remind_datetime) VALUES (?, ?, ?)",
                  (session['user']['username'], reminder_text, remind_datetime))
        conn.commit()
        conn.close()
        return f"Promemoria impostato per il {remind_datetime}: \"{reminder_text}\"."

    # ----- CRONOLOGIA -----
    pattern_cronologia = re.compile(
        r"^(?:cosa (?:ho fatto|abbiamo fatto)|che cosa (?:è successo|è accaduto)|mostrami cosa (?:ho fatto|abbiamo fatto))(?:.*?)(?:il\s+giorno\s+|il\s+)?([\d\/\-]+)",
        re.IGNORECASE
    )
    m_chrono = pattern_cronologia.search(msg)
    if m_chrono:
        data_str = m_chrono.group(1).strip()
        try:
            dt = datetime.strptime(data_str.replace("-", "/"), "%d/%m/%Y")
            data_search = dt.strftime("%Y-%m-%d")
        except Exception as ex:
            return f"Ops, errore nella conversione della data per la cronologia: {ex}"
        conn = sqlite3.connect('assistant_memory.db')
        c = conn.cursor()
        c.execute("SELECT timestamp, richiesta, risposta FROM conversazioni WHERE username = ? AND event_date = ? ORDER BY timestamp ASC",
                  (session['user']['username'], data_search))
        records = c.fetchall()
        conn.close()
        if records:
            out = f"Ecco cosa hai fatto il {data_search}:\n"
            for r in records:
                out += f"{r[0]}: [Tu] {r[1]} | [Assistente] {r[2]}\n"
            tag = get_tags(msg)
            if tag:
                out += f"\n[Tag: {tag}]"
            return out
        else:
            return f"Nessuna attività registrata per il {data_search}."

    # ----- CREDENZIALI: Salvataggio -----
    pattern_salva_credenziali = re.compile(
        r"^(?:salva(?:mi)?\s+(?:le\s+)?credenziali(?:\s+(?:di|per)\s+))([\w\s]+)[\:\-]\s*user(?:name)?\s*:\s*([^,]+)(?:,\s*(?:email|mail)\s*:\s*([^,]+))?,\s*(?:password|pwd)\s*:\s*(.+)$",
        re.IGNORECASE
    )
    m_cred_save = pattern_salva_credenziali.search(msg)
    if m_cred_save:
        reference = m_cred_save.group(1).strip()
        user_val = m_cred_save.group(2).strip()
        email = m_cred_save.group(3).strip() if m_cred_save.group(3) else "non fornita"
        password = m_cred_save.group(4).strip()
        salva_credenziali(session['user']['username'], reference, user_val, email, password)
        return f"Credenziali per '{reference}' salvate con successo. (User: {user_val}, Password: {password})"

    # ----- CREDENZIALI: Visualizzazione -----
    pattern_visualizza_credenziali = re.compile(
        r"^(?:dammi|mostrami|dimmi|visualizza|inviami)(?:\s+(?:le\s+))?credenziali(?:\s+(?:di|per)\s+)([\w\s]+)",
        re.IGNORECASE
    )
    m_cred_view = pattern_visualizza_credenziali.search(msg)
    if m_cred_view:
        reference = m_cred_view.group(1).strip()
        records = get_credenziali(session['user']['username'], reference)
        if records:
            out = f"Credenziali per '{reference}':\n"
            for rec in records:
                out += (f"Dispositivo: {rec[0]}\n   Username: {rec[1]}\n   Email: {rec[2]}\n"
                        f"   Password: {rec[3]}\n   Salvate il: {rec[4]}\n\n")
            return out
        else:
            return f"Nessuna credenziale trovata per '{reference}'."

    # ----- PARAMETRI TECNICI: Salvataggio -----
    pattern_salva_parametri = re.compile(
        r"^(?:salva|memorizza|annota)\s+parametri(?:\s+(?:di|per)\s+)?([\w\s]+)[\:\-]\s*(.+)$",
        re.IGNORECASE
    )
    m_param_save = pattern_salva_parametri.search(msg)
    if m_param_save:
        device = m_param_save.group(1).strip()
        info = m_param_save.group(2).strip()
        salva_parametri_func(session['user']['username'], device, info)
        return f"Parametri per '{device}' salvati: {info}"

    # ----- PARAMETRI TECNICI: Visualizzazione -----
    pattern_visualizza_parametri = re.compile(
        r"^(?:dammi|mostrami|dimmi|visualizza|inviami)(?:\s+(?:i\s+))?(?:parametri|dati|info)(?:\s+(?:di|per)\s+)([\w\s]+)",
        re.IGNORECASE
    )
    m_param_view = pattern_visualizza_parametri.search(msg)
    if m_param_view:
        device = m_param_view.group(1).strip()
        records = get_parametri(session['user']['username'], device)
        if records:
            out = f"Parametri per '{device}':\n"
            for rec in records:
                out += f"Dispositivo: {rec[0]}\n   Info: {rec[1]}\n   Salvati il: {rec[2]}\n\n"
            return out
        else:
            return f"Nessun parametro trovato per '{device}'."

    # ----- POSIZIONE: Salvataggio -----
    pattern_salva_posizione = re.compile(
        r"^salvami la posizione di\s+([\w\s]+)\s*\(?\s*(https?://\S+)",
        re.IGNORECASE
    )
    m_pos = pattern_salva_posizione.search(msg)
    if m_pos:
        person = m_pos.group(1).strip()
        link = m_pos.group(2).strip()
        if not link:
            return "Nessun link fornito per salvare la posizione."
        salva_posizione(session['user']['username'], person, link)
        return f"Posizione per '{person}' salvata con successo."

    # ----- POSIZIONE: Visualizzazione -----
    pattern_visualizza_posizione = re.compile(
        r"^(?:dammi la posizione di)\s+([\w\s]+)",
        re.IGNORECASE
    )
    m_pos_view = pattern_visualizza_posizione.search(msg)
    if m_pos_view:
        person = m_pos_view.group(1).strip()
        record = get_posizione(session['user']['username'], person)
        if record:
            return f"Ecco la posizione di {person}: {record[0]} (salvata il {record[1]})"
        else:
            return f"Nessuna posizione trovata per '{person}'."

    # ----- MEMORIA: Salvataggio della cronologia in un file -----
    pattern_salva_memoria = re.compile(r"^(?:salva\s+memoria|memorizza\s+conversazioni|archivia\s+chat)", re.IGNORECASE)
    if pattern_salva_memoria.search(msg):
        conn = sqlite3.connect('assistant_memory.db')
        c = conn.cursor()
        c.execute("SELECT timestamp, richiesta, risposta FROM conversazioni WHERE username = ? ORDER BY id ASC",
                  (session['user']['username'],))
        records = c.fetchall()
        conn.close()
        out = f"Memoria di {session['user']['username']}:\n"
        for r in records:
            out += f"{r[0]}: [Tu] {r[1]} | [Assistente] {r[2]}\n"
        folder = "memorie"
        os.makedirs(folder, exist_ok=True)
        filename = os.path.join(folder, f"memoria_{session['user']['username']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(out)
            return f"Memoria salvata in {filename}.\nRiepilogo:\n{out}"
        except Exception as ex:
            return f"Problemi nel salvare la memoria: {ex}"

    # ----- RICERCA ERRORI -----
    pattern_ricerca = re.compile(r"^(?:cerca\s+errore:|trova\s+errori:)\s+(.*)", re.IGNORECASE)
    m_ricerca = pattern_ricerca.search(msg)
    if m_ricerca:
        keyword = m_ricerca.group(1).strip()
        conn = sqlite3.connect('assistant_memory.db')
        c = conn.cursor()
        query = ("SELECT timestamp, richiesta, risposta FROM conversazioni "
                 "WHERE (richiesta LIKE ? OR risposta LIKE ?) AND username = ? ORDER BY timestamp DESC")
        param_str = f"%{keyword}%"
        c.execute(query, (param_str, param_str, session['user']['username']))
        records = c.fetchall()
        conn.close()
        if records:
            out = f"Risultati per '{keyword}':\n"
            for r in records:
                out += f"{r[0]}: [Tu] {r[1]} | [Assistente] {r[2]}\n"
            return out
        else:
            return f"Nessun risultato per '{keyword}'."

    # ----- RIASSUNTO DELLA GIORNATA -----
    pattern_riassunto = re.compile(r"^(?:riassumimi\s+la\s+giornata)", re.IGNORECASE)
    if pattern_riassunto.search(msg):
        today = datetime.now().strftime("%Y-%m-%d")
        conn = sqlite3.connect('assistant_memory.db')
        c = conn.cursor()
        c.execute("SELECT richiesta, risposta FROM conversazioni WHERE username = ? AND event_date = ? ORDER BY id ASC",
                  (session['user']['username'], today))
        records = c.fetchall()
        conn.close()
        if records:
            out = f"Riassunto della giornata {today}:\n"
            for r in records:
                out += f"- {r[0]} => {r[1]}\n"
            return out
        else:
            return f"Nessuna attività registrata per oggi ({today})."
    
    return None

# ----------------------------------------------------------------------------
# FUNZIONI DI SALVATAGGIO SUL DATABASE
def salva_interazione(username, richiesta, risposta, event_date=None, tag=None):
    try:
        conn = sqlite3.connect('assistant_memory.db')
        c = conn.cursor()
        timestamp = datetime.now().isoformat()
        c.execute("INSERT INTO conversazioni (timestamp, username, richiesta, risposta, event_date, tag) VALUES (?, ?, ?, ?, ?, ?)",
                  (timestamp, username, richiesta, risposta, event_date, tag))
        conn.commit()
        print(f"[INFO] Salvataggio completato per {username} alle {timestamp}")
    except Exception as e:
        print(f"[ERROR] Errore nel salvataggio: {e}")
    finally:
        conn.close()

def salva_promemoria(username, reminder_text, remind_date):
    conn = sqlite3.connect('assistant_memory.db')
    c = conn.cursor()
    c.execute("INSERT INTO reminders (username, reminder_text, remind_date) VALUES (?, ?, ?)",
              (username, reminder_text, remind_date))
    conn.commit()
    conn.close()

def salva_credenziali(username, reference, user_val, email, password):
    conn = sqlite3.connect('assistant_memory.db')
    c = conn.cursor()
    timestamp = datetime.now().isoformat()
    c.execute("INSERT INTO credentials (username, device, user_val, email, password, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
              (username, reference, user_val, email, password, timestamp))
    conn.commit()
    conn.close()

def get_credenziali(username, reference=None):
    conn = sqlite3.connect('assistant_memory.db')
    c = conn.cursor()
    if reference:
        c.execute("SELECT device, user_val, email, password, timestamp FROM credentials WHERE username = ? AND device LIKE ? ORDER BY timestamp DESC",
                  (username, f"%{reference}%"))
    else:
        c.execute("SELECT device, user_val, email, password, timestamp FROM credentials WHERE username = ? ORDER BY timestamp DESC",
                  (username,))
    records = c.fetchall()
    conn.close()
    return records

def salva_parametri_func(username, device, info):
    conn = sqlite3.connect('assistant_memory.db')
    c = conn.cursor()
    timestamp = datetime.now().isoformat()
    c.execute("INSERT INTO parameters (username, device, info, timestamp) VALUES (?, ?, ?, ?)",
              (username, device, info, timestamp))
    conn.commit()
    conn.close()

def get_parametri(username, device=None):
    conn = sqlite3.connect('assistant_memory.db')
    c = conn.cursor()
    if device:
        c.execute("SELECT device, info, timestamp FROM parameters WHERE username = ? AND device LIKE ? ORDER BY timestamp DESC",
                  (username, f"%{device}%"))
    else:
        c.execute("SELECT device, info, timestamp FROM parameters WHERE username = ? ORDER BY timestamp DESC",
                  (username,))
    records = c.fetchall()
    conn.close()
    return records

# ----------------------------------------------------------------------------
# FUNZIONE PER CONTROLLARE E INVIARE PROMEMORIA
def check_reminders(username):
    now = datetime.now()
    conn = sqlite3.connect('assistant_memory.db')
    c = conn.cursor()
    # Controlla i promemoria non ancora consegnati
    c.execute("SELECT id, reminder_text, remind_date FROM reminders WHERE username = ? AND delivered = 0", (username,))
    reminders = c.fetchall()
    due = []
    for rem in reminders:
        try:
            remind_dt = datetime.strptime(rem[2], "%Y-%m-%d")
        except:
            remind_dt = now
        if now.date() >= remind_dt.date():
            due.append(rem)
            c.execute("UPDATE reminders SET delivered = 1 WHERE id = ?", (rem[0],))
    conn.commit()
    conn.close()
    return due

# ----------------------------------------------------------------------------
# FUNZIONE DI "APPRENDIMENTO" CON AGENTS SDK
def learn_from_interaction(username, conversation):
    agent = Agent(
        name="Learner",
        instructions="Analizza la seguente conversazione e estrai conoscenze utili per migliorare le operazioni future. Se non trovi informazioni rilevanti, restituisci 'Nessuna conoscenza rilevata'."
    )
    result = Runner.run_sync(agent, conversation)
    knowledge_text = result.final_output.strip()
    if knowledge_text and knowledge_text.lower() != "nessuna conoscenza rilevata":
        conn = sqlite3.connect('assistant_memory.db')
        c = conn.cursor()
        timestamp = datetime.now().isoformat()
        c.execute("INSERT INTO knowledge (username, topic, details, timestamp) VALUES (?, ?, ?, ?)",
                  (username, "Conversazione", knowledge_text, timestamp))
        conn.commit()
        conn.close()
    return knowledge_text

# ----------------------------------------------------------------------------
# MODULO DI AUTO-OTTIMIZZAZIONE (CERVELLO)
class SystemOptimizer:
    """
    Il modulo SystemOptimizer monitora lo stato del sistema e, in caso di problemi rilevanti,
    consulta l'Agents SDK per generare e salvare una patch, notificando l'utente.
    """
    def __init__(self, check_interval=3600):
        # Intervallo in secondi per il controllo (ad esempio, ogni 1 ora)
        self.check_interval = check_interval

    def check_system_status(self):
        """
        Controlla lo stato del sistema. Ad esempio, controlla se esistono errori critici.
        Questo esempio controlla un file 'error.log'.
        """
        if os.path.exists('error.log'):
            with open('error.log', 'r', encoding='utf-8') as f:
                logs = f.read()
            if "no such table: conversazioni" in logs:
                return "Errore: Tabella conversazioni mancante"
        return None

    def generate_patch(self, issue):
        prompt = f"Il sistema ha riscontrato il seguente problema:\n{issue}\n" \
                 "Genera una patch in Python per risolvere il problema, nel contesto di un'app Flask che usa SQLite."
        agent = Agent(
            name="Optimizer",
            instructions="Genera una patch di codice per risolvere il problema descritto."
        )
        result = Runner.run_sync(agent, prompt)
        patch_code = result.final_output.strip()
        return patch_code

    def apply_patch(self, patch_code):
        patch_file = "auto_patch.py"
        with open(patch_file, 'w', encoding='utf-8') as f:
            f.write(patch_code)
        print(f"[OPTIMIZER] Patch generata e salvata in {patch_file}")
        return patch_file

    def optimize(self):
        issue = self.check_system_status()
        if issue:
            print(f"[OPTIMIZER] Problema rilevato: {issue}")
            patch = self.generate_patch(issue)
            self.apply_patch(patch)
        else:
            print("[OPTIMIZER] Sistema in stato ottimale.")

    def run(self):
        while True:
            self.optimize()
            sched_time.sleep(self.check_interval)

# Avvia il SystemOptimizer in un thread di background (verifica ogni ora)
optimizer = SystemOptimizer(check_interval=3600)
optimizer_thread = threading.Thread(target=optimizer.run, daemon=True)
optimizer_thread.start()

# ----------------------------------------------------------------------------
# ROTTE DI AUTENTICAZIONE
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        try:
            conn = sqlite3.connect('assistant_memory.db')
            c = conn.cursor()
            c.execute("SELECT username, password, fullname, role FROM technicians WHERE username = ?", (username,))
            tech = c.fetchone()
        except sqlite3.Error as e:
            flash("Errore nel database: " + str(e), "danger")
            return render_template('login.html')
        finally:
            conn.close()
        if tech and check_password_hash(tech[1], password):
            session['user'] = {"username": tech[0], "fullname": tech[2], "role": tech[3]}
            flash("Login effettuato con successo!", "success")
            return redirect(url_for('index'))
        else:
            flash("Accesso negato. Credenziali non valide.", "danger")
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        fullname = request.form.get('fullname')
        hashed_password = generate_password_hash(password)
        try:
            conn = sqlite3.connect('assistant_memory.db')
            c = conn.cursor()
            c.execute("INSERT INTO technicians (username, password, fullname) VALUES (?, ?, ?)",
                      (username, hashed_password, fullname))
            conn.commit()
            flash("Registrazione completata! Ora puoi fare login.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username già in uso. Scegline un altro.", "danger")
        except sqlite3.Error as e:
            flash("Errore nel database: " + str(e), "danger")
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash("Logout effettuato. A presto!", "info")
    return redirect(url_for('login'))

# ----------------------------------------------------------------------------
# ROTTE ADMIN
@app.route('/admin', methods=['GET'])
def admin_panel():
    if 'user' not in session or session['user'].get('role') != 'admin':
        flash("Accesso negato. Area riservata agli amministratori.", "danger")
        return redirect(url_for('index'))
    return render_template('admin_panel.html', user=session['user'])

@app.route('/admin/users', methods=['GET'])
def admin_users():
    if 'user' not in session or session['user'].get('role') != 'admin':
        flash("Accesso negato. Solo gli amministratori possono accedere.", "danger")
        return redirect(url_for('index'))
    conn = sqlite3.connect('assistant_memory.db')
    c = conn.cursor()
    c.execute("SELECT username, fullname FROM technicians ORDER BY username ASC")
    users = c.fetchall()
    conn.close()
    return render_template('admin_users.html', users=users, user=session['user'])

@app.route('/admin/view_user/<username>', methods=['GET'])
def admin_view_user(username):
    if 'user' not in session or session['user'].get('role') != 'admin':
        flash("Accesso negato. Solo gli amministratori possono accedere.", "danger")
        return redirect(url_for('index'))
    conn = sqlite3.connect('assistant_memory.db')
    c = conn.cursor()
    c.execute("""
        SELECT timestamp, richiesta, risposta, event_date, tag
        FROM conversazioni
        WHERE username = ?
        ORDER BY id ASC
    """, (username,))
    chats = c.fetchall()
    c.execute("""
        SELECT reminder_text, remind_date FROM reminders
        WHERE username = ?
        ORDER BY remind_date ASC
    """, (username,))
    reminders = c.fetchall()
    c.execute("""
        SELECT device, user_val, email, password, timestamp FROM credentials
        WHERE username = ?
        ORDER BY timestamp DESC
    """, (username,))
    credentials = c.fetchall()
    c.execute("""
        SELECT device, info, timestamp FROM parameters
        WHERE username = ?
        ORDER BY timestamp DESC
    """, (username,))
    parameters = c.fetchall()
    conn.close()
    return render_template('admin_view_user.html',
                           username=username,
                           chats=chats,
                           reminders=reminders,
                           credentials=credentials,
                           parameters=parameters,
                           user=session['user'])

@app.route('/admin/reports', methods=['GET'])
def admin_reports():
    if 'user' not in session or session['user'].get('role') != 'admin':
        flash("Accesso negato. Solo gli amministratori possono accedere.", "danger")
        return redirect(url_for('index'))
    reports_dir = os.path.join('static', 'reports')
    report_files = os.listdir(reports_dir) if os.path.exists(reports_dir) else []
    return render_template('admin_reports.html', reports=report_files, user=session['user'])

@app.route('/reports/<filename>')
def get_report(filename):
    return send_from_directory(os.path.join('static', 'reports'), filename)

# Rotta per visualizzare la cronologia delle interazioni per una data specifica
@app.route('/history/<username>/<date>')
def history(username, date):
    if 'user' not in session or session['user'].get('role') != 'admin':
        flash("Accesso negato. Solo gli amministratori possono accedere.", "danger")
        return redirect(url_for('index'))
    try:
        datetime.strptime(date, "%Y-%m-%d")
    except Exception as e:
        flash("Formato della data non valido. Deve essere YYYY-MM-DD.", "danger")
        return redirect(url_for('admin_panel'))
    conn = sqlite3.connect('assistant_memory.db')
    c = conn.cursor()
    c.execute("""
        SELECT timestamp, richiesta, risposta, event_date, tag 
        FROM conversazioni 
        WHERE username = ? AND event_date = ? 
        ORDER BY timestamp ASC
    """, (username, date))
    records = c.fetchall()
    conn.close()
    if records:
        history_text = "\n".join([f"{r[0]} - [Tu] {r[1]} | [Assistente] {r[2]} (Tag: {r[4]})" for r in records])
    else:
        history_text = "Nessuna interazione trovata per questa data."
    return render_template('history.html', username=username, date=date, history=history_text)

# ----------------------------------------------------------------------------
# AUTO-AGGIORNAMENTO (PROGRAMMAZIONE "ZONDA")
def auto_aggiornamento():
    log_msg = f"{datetime.now().isoformat()}: Auto-analisi e aggiornamento eseguiti."
    print(log_msg)
    folder = "aggiornamenti"
    os.makedirs(folder, exist_ok=True)
    log_path = os.path.join(folder, "auto_aggiornamento.log")
    with open(log_path, 'a', encoding='utf-8') as log_file:
        log_file.write(log_msg + "\n")
    # Qui puoi aggiungere eventuali altre operazioni, come backup o controlli

def pianifica_auto_aggiornamento():
    schedule.every(2).days.do(auto_aggiornamento)
    while True:
        schedule.run_pending()
        sched_time.sleep(60)

aggiornamento_thread = threading.Thread(target=pianifica_auto_aggiornamento, daemon=True)
aggiornamento_thread.start()

# ----------------------------------------------------------------------------
# ROTTA PER L'APPRENDIMENTO (Agents SDK)
@app.route('/learn', methods=['POST'])
def learn():
    if 'user' not in session:
        flash("Effettua il login per attivare la funzione di apprendimento.", "danger")
        return redirect(url_for('login'))
    conn = sqlite3.connect('assistant_memory.db')
    c = conn.cursor()
    c.execute("SELECT richiesta, risposta FROM conversazioni WHERE username = ? ORDER BY id DESC LIMIT 5",
              (session['user']['username'],))
    interactions = c.fetchall()
    conn.close()
    conversation = "\n".join([f"User: {req}\nAssistant: {res}" for req, res in interactions])
    learned = learn_from_interaction(session['user']['username'], conversation)
    flash(f"Apprendimento completato: {learned}", "info")
    return redirect(url_for('index'))

# ----------------------------------------------------------------------------
# ROTTA PRINCIPALE: Invio messaggio e gestione interazioni
@app.route('/send', methods=['POST'])
def send():
    if 'user' not in session:
        return redirect(url_for('login'))
    raw_message = request.form.get('message')
    user_message = clean_message(raw_message)
    
    event_date = None
    evt_match = re.search(r"il giorno\s+(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{4})", user_message, re.IGNORECASE)
    if evt_match and not re.search(r"^cosa\s+", user_message, re.IGNORECASE):
        try:
            dt_evt = datetime.strptime(evt_match.group(1).replace("-", "/"), "%d/%m/%Y")
            event_date = dt_evt.strftime("%Y-%m-%d")
        except:
            event_date = None
    tag = get_tags(user_message)
    
    if adheres_to_usage_instructions(user_message):
        comando = processa_comando_speciale(user_message)
        if comando:
            risposta = comando
        else:
            file_cmd = processa_comando_file(user_message)
            if file_cmd:
                risposta = file_cmd
            else:
                risposta = "Non riesco a interpretare il comando. Controlla le istruzioni d'uso."
    else:
        conn = sqlite3.connect('assistant_memory.db')
        c = conn.cursor()
        c.execute("SELECT richiesta, risposta FROM conversazioni WHERE username = ? ORDER BY id DESC LIMIT 3",
                  (session['user']['username'],))
        interazioni = c.fetchall()
        conn.close()
        conv_history = ""
        for inter in reversed(interazioni):
            conv_history += f"Tu: {inter[0]}\nAssistente: {inter[1]}\n"
        risposta = generate_ai_response(user_message, conv_history, session['user'])
    
    salva_interazione(session['user']['username'], user_message, risposta, event_date, tag)
    return redirect(url_for('index'))

# Rotta per Upload di file
@app.route('/upload', methods=['POST'])
def upload():
    if 'user' not in session:
        return redirect(url_for('login'))
    if 'photo' not in request.files:
        flash("Nessun file selezionato.", "danger")
        return redirect(url_for('index'))
    file = request.files['photo']
    if file.filename == "":
        flash("File non selezionato.", "danger")
        return redirect(url_for('index'))
    folder = os.path.join('static', 'reports')
    os.makedirs(folder, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    filename = f"report_{timestamp}_{file.filename}"
    filepath = os.path.join(folder, filename)
    file.save(filepath)
    flash("Rapporto caricato correttamente!", "success")
    salva_interazione(session['user']['username'], "Upload rapporto", f"Rapporto salvato come {filename}", None, None)
    return redirect(url_for('index'))

# Rotta per la creazione di un promemoria
@app.route('/create_reminder', methods=['POST'])
def create_reminder():
    date = request.form.get("date")
    reminder_text = request.form.get("reminder_text")
    salva_promemoria(session['user']['username'], reminder_text, date)
    flash("Promemoria creato!", "success")
    salva_interazione(session['user']['username'], f"Crea promemoria per {date}", reminder_text, date, None)
    return redirect(url_for('index'))

# ----------------------------------------------------------------------------
# Rotta principale (Home) per visualizzare interazioni
@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    is_admin = (session['user'].get('role') == 'admin')
    for rem in check_reminders(session['user']['username']):
        flash(f"Promemoria: {rem[1]}", "info")
    conn = sqlite3.connect('assistant_memory.db')
    c = conn.cursor()
    c.execute("SELECT timestamp, username, richiesta, risposta, event_date, tag FROM conversazioni WHERE username = ? ORDER BY id ASC",
              (session['user']['username'],))
    conversazioni = c.fetchall()
    conn.close()
    return render_template('index.html', conversazioni=conversazioni, user=session['user'], is_admin=is_admin)

# Avvio dell'applicazione Flask
if __name__ == '__main__':
    init_db()  # Esegui l'inizializzazione del database all'avvio
    app.run(debug=True)