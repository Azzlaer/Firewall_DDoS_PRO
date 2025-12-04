"""
main.py
DDoS Defender Pro - Enterprise (Tkinter + Tabs + Tools)

Requisitos:
 - Ejecutar en Windows (netsh advfirewall)
 - Ejecutar como Administrador para bloquear IPs
 - psutil, requests, matplotlib, tkinter

Funcionalidad:
 - Monitor de conexiones TCP en tiempo real
 - Auto-bloqueo por threshold + AbuseIPDB (opcional)
 - Logs en SQLite + fichero
 - Alertas por Email / Telegram / Discord (webhooks) con emojis
 - GUI en pestañas:
    📊 Dashboard
    🚫 Firewall & Bloqueos
    📝 Logs
    📡 Webhooks & Alertas
    ⚙ Sistema & Reglas
    🛠 Herramientas (WHOIS / Ping / GeoIP)

Creado por ChatGPT OpenAI + Azzlaer para LatinBattle.com
"""

import os
import sys
import time
import threading
import sqlite3
import subprocess
import ctypes
import smtplib
from email.message import EmailMessage
from datetime import datetime
import configparser
import queue
import socket

import psutil
import requests

import tkinter as tk
from tkinter import ttk, messagebox

from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


# ----------------------------------------------------------------------
# CONFIG MANAGER
# ----------------------------------------------------------------------
class ConfigManager:
    def __init__(self, path="config.ini"):
        self.path = path
        self.cfg = configparser.ConfigParser()
        if not os.path.exists(self.path):
            self._create_default()
        self.read()

    def _create_default(self):
        self.cfg["GENERAL"] = {
            "monitor_interval_sec": "1",
            "auto_block_enabled": "yes",
            "auto_block_threshold": "50",
            "threshold_action": "notify",   # notify | block
            "auto_block_temporary_minutes": "30",
            "max_history_points": "120",
            "whitelist": "",
            "blacklist": ""
        }
        self.cfg["ABUSEIPDB"] = {
            "enabled": "no",
            "api_key": "",
            "min_score_for_block": "50"
        }
        self.cfg["ALERTS"] = {
            "email_enabled": "no",
            "smtp_server": "",
            "smtp_port": "587",
            "smtp_user": "",
            "smtp_password": "",
            "email_from": "",
            "email_to": "",
            "telegram_enabled": "no",
            "telegram_url": "",
            "discord_enabled": "no",
            "discord_url": ""
        }
        self.cfg["LOGGING"] = {
            "log_db": "ddos_defender_logs.db",
            "log_file": "ddos_defender.log"
        }
        with open(self.path, "w", encoding="utf-8") as f:
            self.cfg.write(f)

    def read(self):
        self.cfg.read(self.path, encoding="utf-8")

    def save(self):
        with open(self.path, "w", encoding="utf-8") as f:
            self.cfg.write(f)

    def getint(self, section, option, fallback=0):
        try:
            return self.cfg.getint(section, option)
        except Exception:
            return fallback

    def getboolean(self, section, option, fallback=False):
        try:
            return self.cfg.getboolean(section, option)
        except Exception:
            return fallback

    def get(self, section, option, fallback=""):
        try:
            return self.cfg.get(section, option)
        except Exception:
            return fallback

    def set(self, section, option, value):
        if section not in self.cfg:
            self.cfg[section] = {}
        self.cfg[section][option] = str(value)
        self.save()


# ----------------------------------------------------------------------
# LOGGER (SQLite + fichero)
# ----------------------------------------------------------------------
class Logger:
    def __init__(self, db_path, log_file):
        self.db_path = db_path
        self.log_file = log_file
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT,
                level TEXT,
                ip TEXT,
                action TEXT,
                details TEXT
            )
        """)
        conn.commit()
        conn.close()

    def log(self, level, ip, action, details=""):
        ts = datetime.utcnow().isoformat() + "Z"
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            "INSERT INTO events (ts, level, ip, action, details) VALUES (?, ?, ?, ?, ?)",
            (ts, level, ip, action, details)
        )
        conn.commit()
        conn.close()

        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(f"{ts} [{level}] {ip} {action} {details}\n")


# ----------------------------------------------------------------------
# Utilidades Windows / Firewall
# ----------------------------------------------------------------------
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def add_firewall_block(ip, name=None):
    if not name:
        name = f"DDOS_Defender_{ip}_{int(time.time())}"
    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={name}", "dir=in", "action=block", f"remoteip={ip}"
    ]
    try:
        subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return name
    except Exception:
        return None


def del_firewall_rule(name):
    cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"]
    try:
        subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False


# ----------------------------------------------------------------------
# AbuseIPDB Lookup
# ----------------------------------------------------------------------
def abuseipdb_score(ip, api_key, timeout=5):
    if not api_key:
        return None
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Accept": "application/json", "Key": api_key}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        r = requests.get(url, headers=headers, params=params, timeout=timeout)
        if r.status_code == 200:
            data = r.json().get("data", {})
            return data.get("abuseConfidenceScore")
        return None
    except Exception:
        return None


# ----------------------------------------------------------------------
# ALERTAS (Email / Telegram / Discord) con emojis
# ----------------------------------------------------------------------
def send_email(cfg, subject, body):
    if not cfg.getboolean("ALERTS", "email_enabled", False):
        return False
    try:
        smtp_server = cfg.get("ALERTS", "smtp_server", "")
        smtp_port = cfg.getint("ALERTS", "smtp_port", 587)
        user = cfg.get("ALERTS", "smtp_user", "")
        pwd = cfg.get("ALERTS", "smtp_password", "")
        frm = cfg.get("ALERTS", "email_from", "")
        tos = cfg.get("ALERTS", "email_to", "")

        if not (smtp_server and user and frm and tos):
            return False

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = frm
        msg["To"] = tos
        msg.set_content(body)

        s = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
        s.starttls()
        if pwd:
            s.login(user, pwd)
        s.send_message(msg)
        s.quit()
        return True
    except Exception:
        return False


def send_telegram(cfg, message):
    if not cfg.getboolean("ALERTS", "telegram_enabled", False):
        return False
    url = cfg.get("ALERTS", "telegram_url", "")
    if not url:
        return False
    try:
        requests.post(url, data={"text": message}, timeout=5)
        return True
    except Exception:
        return False


def send_discord(cfg, message):
    if not cfg.getboolean("ALERTS", "discord_enabled", False):
        return False
    url = cfg.get("ALERTS", "discord_url", "")
    if not url:
        return False
    try:
        requests.post(url, json={"content": message}, timeout=5)
        return True
    except Exception:
        return False


def notify_all_helper(cfg, subject, body, level="INFO"):
    emoji_map = {
        "INFO": "ℹ️",
        "WARN": "⚠️",
        "ERROR": "❌",
        "CRITICAL": "🚨"
    }
    icon = emoji_map.get(level.upper(), "📡")

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    host = os.getenv("COMPUTERNAME") or os.getenv("HOSTNAME") or "Host-desconocido"

    full_body = (
        f"{icon} {subject}\n"
        f"💻 Host: {host}\n"
        f"🕒 {ts}\n\n"
        f"{body}"
    )

    send_email(cfg, f"{icon} {subject}", full_body)
    send_telegram(cfg, full_body)
    send_discord(cfg, full_body)


# ----------------------------------------------------------------------
# Hilo monitor
# ----------------------------------------------------------------------
class MonitorThread(threading.Thread):
    def __init__(self, cfg, out_queue, stop_event):
        super().__init__(daemon=True)
        self.cfg = cfg
        self.out_queue = out_queue
        self.stop_event = stop_event

    def run(self):
        while not self.stop_event.is_set():
            interval = self.cfg.getint("GENERAL", "monitor_interval_sec", 1)
            try:
                conns = psutil.net_connections(kind='tcp')
            except Exception:
                conns = []

            ip_counts = {}
            total = 0

            for c in conns:
                if c.raddr:
                    ip = c.raddr.ip
                    if ip.startswith("127.") or ip == "::1":
                        continue
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
                    total += 1

            self.out_queue.put((ip_counts, total))
            time.sleep(interval)


# ----------------------------------------------------------------------
# GUI PRINCIPAL
# ----------------------------------------------------------------------
class App:
    def __init__(self, root):
        self.root = root
        self.root.title("DDoS Defender Pro - Enterprise")
        self.root.geometry("1200x750")

        self.cfg = ConfigManager("config.ini")
        log_db = self.cfg.get("LOGGING", "log_db", "ddos_defender_logs.db")
        log_file = self.cfg.get("LOGGING", "log_file", "ddos_defender.log")
        self.logger = Logger(log_db, log_file)

        self.rule_names = {}   # ip -> firewall rule name
        self.temp_timers = {}  # ip -> Timer

        self.history = []
        self.max_history = self.cfg.getint("GENERAL", "max_history_points", 120)

        # Cola y evento para monitor
        self.queue = queue.Queue()
        self.stop_event = threading.Event()
        self.monitor = None

        # Construcción de pestañas
        self._build_tabs_ui()

        # Arranca el monitor por defecto
        self.start_monitor()

        # Procesado periódico de la cola
        self.root.after(200, self._process_queue)

        # Pre-bloqueo de blacklist y refresco inicial
        self._preblock_blacklist()
        self.refresh_logs()
        self._update_block_tab()

    # ------------------------------------------------------------------
    # Construcción de pestañas
    # ------------------------------------------------------------------
    def _build_tabs_ui(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Tabs
        self.tab_dashboard = ttk.Frame(self.notebook)
        self.tab_firewall = ttk.Frame(self.notebook)
        self.tab_logs = ttk.Frame(self.notebook)
        self.tab_webhooks = ttk.Frame(self.notebook)
        self.tab_config = ttk.Frame(self.notebook)
        self.tab_tools = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_dashboard, text="📊 Dashboard")
        self.notebook.add(self.tab_firewall, text="🚫 Firewall & Bloqueos")
        self.notebook.add(self.tab_logs, text="📝 Logs")
        self.notebook.add(self.tab_webhooks, text="📡 Webhooks & Alertas")
        self.notebook.add(self.tab_config, text="⚙ Sistema & Reglas")
        self.notebook.add(self.tab_tools, text="🛠 Herramientas")

        self._build_tab_dashboard()
        self._build_tab_firewall()
        self._build_tab_logs()
        self._build_tab_webhooks()
        self._build_tab_config()
        self._build_tab_tools()

    # ------------------------ TAB: DASHBOARD ---------------------------
    def _build_tab_dashboard(self):
        top = ttk.Frame(self.tab_dashboard)
        top.pack(side=tk.TOP, fill=tk.X, padx=8, pady=6)

        self.lbl_status = ttk.Label(top, text="Estado: Monitoreando...")
        self.lbl_status.pack(side=tk.LEFT)

        self.lbl_total = ttk.Label(top, text="Conexiones: 0")
        self.lbl_total.pack(side=tk.LEFT, padx=10)

        host = os.getenv("COMPUTERNAME") or os.getenv("HOSTNAME") or "Host-desconocido"
        ttk.Label(top, text=f"Host: {host}").pack(side=tk.LEFT, padx=10)

        ttk.Button(top, text="Abrir carpeta", command=self.open_folder).pack(side=tk.RIGHT, padx=4)

        middle = ttk.Frame(self.tab_dashboard)
        middle.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        # Tabla de conexiones
        self.table = ttk.Treeview(middle, columns=("ip", "count"), show="headings")
        self.table.heading("ip", text="IP Remota")
        self.table.heading("count", text="Conexiones")
        self.table.column("ip", width=280)
        self.table.column("count", width=100, anchor=tk.CENTER)
        self.table.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        # Gráfico
        fig = Figure(figsize=(6, 2.5))
        self.ax = fig.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(fig, master=middle)
        self.canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.X, pady=5)

        # Botones rápidos
        bottom = ttk.Frame(self.tab_dashboard)
        bottom.pack(side=tk.TOP, fill=tk.X, padx=8, pady=4)

        ttk.Button(bottom, text="Start Monitor", command=self.start_monitor).pack(side=tk.LEFT, padx=4)
        ttk.Button(bottom, text="Stop Monitor", command=self.stop_monitor).pack(side=tk.LEFT, padx=4)

        ttk.Button(bottom, text="Bloquear IP seleccionada",
                   command=self.block_selected).pack(side=tk.LEFT, padx=4)
        ttk.Button(bottom, text="Desbloquear IP seleccionada",
                   command=self.unblock_selected).pack(side=tk.LEFT, padx=4)
        ttk.Button(bottom, text="Check AbuseIPDB",
                   command=self.check_selected_abuse).pack(side=tk.LEFT, padx=4)

    # ------------------------ TAB: FIREWALL ----------------------------
    def _build_tab_firewall(self):
        frm = ttk.Frame(self.tab_firewall)
        frm.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        ttk.Label(frm, text="IP bloqueadas actualmente:").pack(anchor=tk.W)

        self.lst_blocked = tk.Listbox(frm, height=15, font=("Consolas", 10))
        self.lst_blocked.pack(fill=tk.BOTH, expand=True, pady=4)

        btns = ttk.Frame(frm)
        btns.pack(fill=tk.X, pady=4)

        ttk.Button(btns, text="Desbloquear seleccionada",
                   command=self.unblock_from_tab).pack(side=tk.LEFT, padx=4)

        ttk.Label(frm, text="Bloqueo / Desbloqueo manual:").pack(anchor=tk.W, pady=(10, 0))
        self.entry_manual_ip = ttk.Entry(frm)
        self.entry_manual_ip.pack(fill=tk.X, pady=2)

        btns2 = ttk.Frame(frm)
        btns2.pack(fill=tk.X, pady=4)

        ttk.Button(btns2, text="Bloquear IP",
                   command=self.manual_block).pack(side=tk.LEFT, padx=4)
        ttk.Button(btns2, text="Desbloquear (nombre de regla)",
                   command=self.manual_unblock_by_rule).pack(side=tk.LEFT, padx=4)

        self.lbl_admin = ttk.Label(frm, text="")
        self.lbl_admin.pack(anchor=tk.W, pady=4)
        self._update_admin_label()

    def _update_admin_label(self):
        if is_admin():
            self.lbl_admin.config(text="Permisos: Administrador ✔")
        else:
            self.lbl_admin.config(text="Permisos: NO Administrador ❌ (bloqueos no funcionarán)")

    # ------------------------ TAB: LOGS --------------------------------
    def _build_tab_logs(self):
        frm = ttk.Frame(self.tab_logs)
        frm.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        top = ttk.Frame(frm)
        top.pack(fill=tk.X)
        ttk.Button(top, text="Refrescar logs", command=self.refresh_logs).pack(side=tk.LEFT, padx=4)

        self.txt_logs = tk.Text(frm, height=20, background="#111111", foreground="#00FF00")
        self.txt_logs.pack(fill=tk.BOTH, expand=True, pady=4)

    # ------------------------ TAB: WEBHOOKS & ALERTAS ------------------
    def _build_tab_webhooks(self):
        frm = ttk.Frame(self.tab_webhooks)
        frm.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        frame_email = ttk.LabelFrame(frm, text="Email")
        frame_email.pack(fill=tk.X, pady=4)
        self.var_email_enabled = tk.BooleanVar(
            value=self.cfg.getboolean("ALERTS", "email_enabled", False)
        )
        ttk.Checkbutton(frame_email, text="Habilitar alertas por Email",
                        variable=self.var_email_enabled).pack(anchor=tk.W, padx=6, pady=2)

        ttk.Label(frame_email, text="SMTP server:port").pack(anchor=tk.W, padx=6)
        self.entry_smtp = ttk.Entry(frame_email)
        self.entry_smtp.pack(fill=tk.X, padx=6, pady=2)
        smtp_server = self.cfg.get("ALERTS", "smtp_server", "")
        smtp_port = self.cfg.get("ALERTS", "smtp_port", "587")
        self.entry_smtp.insert(0, f"{smtp_server}:{smtp_port}")

        ttk.Label(frame_email, text="SMTP user").pack(anchor=tk.W, padx=6)
        self.entry_smtp_user = ttk.Entry(frame_email)
        self.entry_smtp_user.pack(fill=tk.X, padx=6, pady=2)
        self.entry_smtp_user.insert(0, self.cfg.get("ALERTS", "smtp_user", ""))

        ttk.Label(frame_email, text="SMTP password (texto plano)").pack(anchor=tk.W, padx=6)
        self.entry_smtp_pwd = ttk.Entry(frame_email, show="*")
        self.entry_smtp_pwd.pack(fill=tk.X, padx=6, pady=2)
        self.entry_smtp_pwd.insert(0, self.cfg.get("ALERTS", "smtp_password", ""))

        ttk.Label(frame_email, text="Email from").pack(anchor=tk.W, padx=6)
        self.entry_email_from = ttk.Entry(frame_email)
        self.entry_email_from.pack(fill=tk.X, padx=6, pady=2)
        self.entry_email_from.insert(0, self.cfg.get("ALERTS", "email_from", ""))

        ttk.Label(frame_email, text="Email to (coma separada)").pack(anchor=tk.W, padx=6)
        self.entry_email_to = ttk.Entry(frame_email)
        self.entry_email_to.pack(fill=tk.X, padx=6, pady=2)
        self.entry_email_to.insert(0, self.cfg.get("ALERTS", "email_to", ""))

        frame_telegram = ttk.LabelFrame(frm, text="Telegram")
        frame_telegram.pack(fill=tk.X, pady=4)
        self.var_tg_enabled = tk.BooleanVar(
            value=self.cfg.getboolean("ALERTS", "telegram_enabled", False)
        )
        ttk.Checkbutton(frame_telegram, text="Habilitar Telegram webhook",
                        variable=self.var_tg_enabled).pack(anchor=tk.W, padx=6, pady=2)
        ttk.Label(frame_telegram, text="Telegram sendMessage URL").pack(anchor=tk.W, padx=6)
        self.entry_tg_url = ttk.Entry(frame_telegram)
        self.entry_tg_url.pack(fill=tk.X, padx=6, pady=2)
        self.entry_tg_url.insert(0, self.cfg.get("ALERTS", "telegram_url", ""))

        frame_discord = ttk.LabelFrame(frm, text="Discord")
        frame_discord.pack(fill=tk.X, pady=4)
        self.var_dc_enabled = tk.BooleanVar(
            value=self.cfg.getboolean("ALERTS", "discord_enabled", False)
        )
        ttk.Checkbutton(frame_discord, text="Habilitar Discord webhook",
                        variable=self.var_dc_enabled).pack(anchor=tk.W, padx=6, pady=2)
        ttk.Label(frame_discord, text="Discord webhook URL").pack(anchor=tk.W, padx=6)
        self.entry_dc_url = ttk.Entry(frame_discord)
        self.entry_dc_url.pack(fill=tk.X, padx=6, pady=2)
        self.entry_dc_url.insert(0, self.cfg.get("ALERTS", "discord_url", ""))

        btns = ttk.Frame(frm)
        btns.pack(fill=tk.X, pady=8)
        ttk.Button(btns, text="Guardar alertas", command=self.save_alerts_from_ui).pack(side=tk.LEFT, padx=4)
        ttk.Button(btns, text="Enviar test (WARN)",
                   command=self.send_test_alert).pack(side=tk.LEFT, padx=4)

    # ------------------------ TAB: CONFIG / SISTEMA --------------------
    def _build_tab_config(self):
        frm = ttk.Frame(self.tab_config)
        frm.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # Auto-bloqueo
        frame_auto = ttk.LabelFrame(frm, text="Auto-mitigación")
        frame_auto.pack(fill=tk.X, pady=4)

        self.var_auto_block = tk.BooleanVar(
            value=self.cfg.getboolean("GENERAL", "auto_block_enabled", True)
        )
        ttk.Checkbutton(frame_auto, text="Habilitar auto-bloqueo",
                        variable=self.var_auto_block).pack(anchor=tk.W, padx=6, pady=2)

        # Selección del modo de threshold
        self.var_threshold_action = tk.StringVar(
            value=self.cfg.get("GENERAL", "threshold_action", "notify")
        )

        ttk.Label(frame_auto, text="Acción al superar threshold:").pack(anchor=tk.W, padx=6)

        rb1 = ttk.Radiobutton(frame_auto, text="Solo notificar",
                              variable=self.var_threshold_action, value="notify")
        rb2 = ttk.Radiobutton(frame_auto, text="Notificar + Bloquear IP automáticamente",
                              variable=self.var_threshold_action, value="block")

        rb1.pack(anchor=tk.W, padx=16)
        rb2.pack(anchor=tk.W, padx=16)

        # Threshold numérico
        row_auto = ttk.Frame(frame_auto)
        row_auto.pack(fill=tk.X, padx=6, pady=2)
        ttk.Label(row_auto, text="Threshold conexiones desde misma IP:").pack(side=tk.LEFT)
        self.spin_threshold = tk.Spinbox(row_auto, from_=1, to=100000, width=8)
        self.spin_threshold.pack(side=tk.LEFT, padx=6)
        self.spin_threshold.delete(0, "end")
        self.spin_threshold.insert(0, self.cfg.getint("GENERAL", "auto_block_threshold", 50))

        # Duración
        row_temp = ttk.Frame(frame_auto)
        row_temp.pack(fill=tk.X, padx=6, pady=2)
        ttk.Label(row_temp, text="Duración bloqueo (min, 0 = permanente):").pack(side=tk.LEFT)
        self.spin_temp = tk.Spinbox(row_temp, from_=0, to=60*24, width=8)
        self.spin_temp.pack(side=tk.LEFT, padx=6)
        self.spin_temp.delete(0, "end")
        self.spin_temp.insert(0, self.cfg.getint("GENERAL", "auto_block_temporary_minutes", 30))

        # Intervalo
        row_interval = ttk.Frame(frame_auto)
        row_interval.pack(fill=tk.X, padx=6, pady=2)
        ttk.Label(row_interval, text="Intervalo de monitor (segundos):").pack(side=tk.LEFT)
        self.spin_interval = tk.Spinbox(row_interval, from_=1, to=60, width=8)
        self.spin_interval.pack(side=tk.LEFT, padx=6)
        self.spin_interval.delete(0, "end")
        self.spin_interval.insert(0, self.cfg.getint("GENERAL", "monitor_interval_sec", 1))

        # Historial gráfico
        row_hist = ttk.Frame(frame_auto)
        row_hist.pack(fill=tk.X, padx=6, pady=2)
        ttk.Label(row_hist, text="Historial máximo puntos (gráfico):").pack(side=tk.LEFT)
        self.spin_history = tk.Spinbox(row_hist, from_=10, to=1000, width=8)
        self.spin_history.pack(side=tk.LEFT, padx=6)
        self.spin_history.delete(0, "end")
        self.spin_history.insert(0, self.max_history)

        # AbuseIPDB
        frame_abuse = ttk.LabelFrame(frm, text="AbuseIPDB")
        frame_abuse.pack(fill=tk.X, pady=4)
        ttk.Label(frame_abuse, text="API Key").pack(anchor=tk.W, padx=6)
        self.entry_abuse_key = ttk.Entry(frame_abuse)
        self.entry_abuse_key.pack(fill=tk.X, padx=6, pady=2)
        self.entry_abuse_key.insert(0, self.cfg.get("ABUSEIPDB", "api_key", ""))

        ttk.Label(frame_abuse, text="Score mínimo para bloquear (0-100):").pack(anchor=tk.W, padx=6)
        self.spin_abuse_score = tk.Spinbox(frame_abuse, from_=0, to=100, width=6)
        self.spin_abuse_score.pack(anchor=tk.W, padx=6, pady=2)
        self.spin_abuse_score.delete(0, "end")
        self.spin_abuse_score.insert(0, self.cfg.getint("ABUSEIPDB", "min_score_for_block", 50))

        # Whitelist / Blacklist
        frame_wb = ttk.LabelFrame(frm, text="Whitelist / Blacklist")
        frame_wb.pack(fill=tk.BOTH, pady=4, expand=True)
        ttk.Label(frame_wb, text="Whitelist (IPs separadas por coma):").pack(anchor=tk.W, padx=6)
        self.entry_whitelist = ttk.Entry(frame_wb)
        self.entry_whitelist.pack(fill=tk.X, padx=6, pady=2)
        self.entry_whitelist.insert(0, self.cfg.get("GENERAL", "whitelist", ""))

        ttk.Label(frame_wb, text="Blacklist (IPs separadas por coma):").pack(anchor=tk.W, padx=6)
        self.entry_blacklist = ttk.Entry(frame_wb)
        self.entry_blacklist.pack(fill=tk.X, padx=6, pady=2)
        self.entry_blacklist.insert(0, self.cfg.get("GENERAL", "blacklist", ""))

        btns = ttk.Frame(frm)
        btns.pack(fill=tk.X, pady=8)
        ttk.Button(btns, text="Guardar configuración",
                   command=self.save_config_from_ui).pack(side=tk.LEFT, padx=4)

    # ------------------------ TAB: HERRAMIENTAS ------------------------
    def _build_tab_tools(self):
        frm = ttk.Frame(self.tab_tools)
        frm.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        title = ttk.Label(frm, text="Herramientas de Análisis & Red", font=("Segoe UI", 12, "bold"))
        title.pack(anchor=tk.CENTER, pady=10)

        # WHOIS + Reverse DNS
        box1 = ttk.LabelFrame(frm, text="Lookup WHOIS / Reverse DNS")
        box1.pack(fill=tk.X, pady=6)

        self.entry_lookup = ttk.Entry(box1)
        self.entry_lookup.pack(fill=tk.X, padx=6, pady=6)
        self.entry_lookup.insert(0, "8.8.8.8")

        btns = ttk.Frame(box1)
        btns.pack()
        ttk.Button(btns, text="WHOIS Lookup", command=self.tool_whois).pack(side=tk.LEFT, padx=4)
        ttk.Button(btns, text="Reverse DNS", command=self.tool_reverse_dns).pack(side=tk.LEFT, padx=4)

        # Ping test
        box2 = ttk.LabelFrame(frm, text="Ping Test")
        box2.pack(fill=tk.X, pady=6)

        self.entry_ping = ttk.Entry(box2)
        self.entry_ping.pack(fill=tk.X, padx=6, pady=6)
        self.entry_ping.insert(0, "google.com")

        ttk.Button(box2, text="Ping 4 veces", command=self.tool_ping).pack(padx=6, pady=4)

        # GeoIP
        box3 = ttk.LabelFrame(frm, text="GeoIP Lookup")
        box3.pack(fill=tk.X, pady=6)

        self.entry_geoip = ttk.Entry(box3)
        self.entry_geoip.pack(fill=tk.X, padx=6, pady=6)
        self.entry_geoip.insert(0, "8.8.8.8")

        ttk.Button(box3, text="Buscar ubicación", command=self.tool_geoip).pack(padx=6, pady=4)

        # Salida resultados
        self.txt_tools = tk.Text(frm, background="#111111", foreground="#00FFAA", height=16)
        self.txt_tools.pack(fill=tk.BOTH, expand=True, pady=8)

    # ======================== FUNCIONES DE TOOLS ============================
    def _tools_write(self, txt):
        self.txt_tools.insert(tk.END, txt + "\n")
        self.txt_tools.see(tk.END)

    def tool_whois(self):
        target = self.entry_lookup.get().strip()
        self.txt_tools.delete(1.0, tk.END)
        self._tools_write(f"🔍 WHOIS Lookup: {target}\n")
        try:
            result = subprocess.check_output(f"whois {target}", shell=True, text=True, stderr=subprocess.STDOUT)
            self._tools_write(result)
        except Exception as e:
            self._tools_write(f"[ERROR] WHOIS no disponible o no instalado: {e}")

    def tool_reverse_dns(self):
        target = self.entry_lookup.get().strip()
        self.txt_tools.delete(1.0, tk.END)
        self._tools_write(f"💠 Reverse DNS Lookup: {target}\n")
        try:
            host = socket.gethostbyaddr(target)
            self._tools_write(f"Dominio → {host[0]}")
        except Exception:
            self._tools_write("No existe PTR / sin resolución")

    def tool_ping(self):
        host = self.entry_ping.get().strip()
        self.txt_tools.delete(1.0, tk.END)
        self._tools_write(f"📡 Ping → {host}\n")
        try:
            out = subprocess.check_output(f"ping -n 4 {host}", shell=True, text=True)
            self._tools_write(out)
        except Exception as e:
            self._tools_write(f"[ERROR] {e}")

    def tool_geoip(self):
        ip = self.entry_geoip.get().strip()
        self.txt_tools.delete(1.0, tk.END)
        self._tools_write(f"🌍 GeoIP Lookup: {ip}\n")
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=5).json()
            for k, v in r.items():
                self._tools_write(f"{k}: {v}")
        except Exception:
            self._tools_write("Error al consultar API GeoIP.")

    # ------------------------------------------------------------------
    # Funciones de guardado de configuración / alertas
    # ------------------------------------------------------------------
    def save_alerts_from_ui(self):
        smtp = self.entry_smtp.get().strip()
        if ":" in smtp:
            server, port = smtp.split(":", 1)
        else:
            server, port = smtp, "587"

        self.cfg.set("ALERTS", "smtp_server", server)
        self.cfg.set("ALERTS", "smtp_port", port)
        self.cfg.set("ALERTS", "smtp_user", self.entry_smtp_user.get().strip())
        self.cfg.set("ALERTS", "smtp_password", self.entry_smtp_pwd.get().strip())
        self.cfg.set("ALERTS", "email_from", self.entry_email_from.get().strip())
        self.cfg.set("ALERTS", "email_to", self.entry_email_to.get().strip())
        self.cfg.set("ALERTS", "email_enabled", "yes" if self.var_email_enabled.get() else "no")

        self.cfg.set("ALERTS", "telegram_url", self.entry_tg_url.get().strip())
        self.cfg.set("ALERTS", "telegram_enabled", "yes" if self.var_tg_enabled.get() else "no")

        self.cfg.set("ALERTS", "discord_url", self.entry_dc_url.get().strip())
        self.cfg.set("ALERTS", "discord_enabled", "yes" if self.var_dc_enabled.get() else "no")

        messagebox.showinfo("Alertas", "Configuración de alertas guardada.")

    def send_test_alert(self):
        subj = "[DDoS Defender] Test de alerta"
        body = "Este es un mensaje de prueba del sistema de alertas."
        threading.Thread(
            target=notify_all_helper,
            args=(self.cfg, subj, body, "WARN"),
            daemon=True
        ).start()
        messagebox.showinfo("Test", "Se ha enviado una alerta de prueba (si está configurado).")

    def save_config_from_ui(self):
        # GENERAL
        self.cfg.set("GENERAL", "auto_block_enabled", "yes" if self.var_auto_block.get() else "no")
        self.cfg.set("GENERAL", "threshold_action", self.var_threshold_action.get())
        self.cfg.set("GENERAL", "auto_block_threshold", self.spin_threshold.get())
        self.cfg.set("GENERAL", "auto_block_temporary_minutes", self.spin_temp.get())
        self.cfg.set("GENERAL", "monitor_interval_sec", self.spin_interval.get())
        self.cfg.set("GENERAL", "whitelist", self.entry_whitelist.get().strip())
        self.cfg.set("GENERAL", "blacklist", self.entry_blacklist.get().strip())

        # Historial
        try:
            self.max_history = int(self.spin_history.get())
        except Exception:
            self.max_history = 120
        self.cfg.set("GENERAL", "max_history_points", str(self.max_history))

        # AbuseIPDB
        self.cfg.set("ABUSEIPDB", "api_key", self.entry_abuse_key.get().strip())
        self.cfg.set("ABUSEIPDB", "min_score_for_block", self.spin_abuse_score.get())

        self.cfg.read()
        messagebox.showinfo("Configuración", "Configuración guardada en config.ini")

    # ------------------------------------------------------------------
    # Lógica de monitor y actualización de UI
    # ------------------------------------------------------------------
    def _process_queue(self):
        try:
            while not self.queue.empty():
                ip_counts, total = self.queue.get_nowait()
                self._update_ui_with_counts(ip_counts, total)
        except queue.Empty:
            pass
        self.root.after(200, self._process_queue)

    def _update_ui_with_counts(self, ip_counts, total):
        # Tabla
        for item in self.table.get_children():
            self.table.delete(item)
        for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
            self.table.insert("", tk.END, values=(ip, count))

        self.lbl_total.config(text=f"Conexiones: {total}")

        # Historial
        self.history.append(total)
        if len(self.history) > self.max_history:
            self.history = self.history[-self.max_history:]
        self._redraw_chart()

        # Auto-bloqueo
        self._auto_block_check(ip_counts)

    def _redraw_chart(self):
        try:
            self.ax.clear()
            self.ax.plot(self.history)
            self.ax.set_title("Conexiones totales (historial)")
            self.ax.set_ylabel("Conexiones")
            self.canvas.draw()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Auto-bloqueo con modos notify / block
    # ------------------------------------------------------------------
    def _auto_block_check(self, ip_counts):
        if not self.cfg.getboolean("GENERAL", "auto_block_enabled", True):
            return

        threshold = self.cfg.getint("GENERAL", "auto_block_threshold", 50)
        temp_minutes = self.cfg.getint("GENERAL", "auto_block_temporary_minutes", 30)
        mode = self.cfg.get("GENERAL", "threshold_action", "notify")

        whitelist = [
            x.strip() for x in self.cfg.get("GENERAL", "whitelist", "").split(",") if x.strip()
        ]
        abuse_api_key = self.cfg.get("ABUSEIPDB", "api_key", "").strip()
        abuse_min = self.cfg.getint("ABUSEIPDB", "min_score_for_block", 50)

        for ip, count in ip_counts.items():
            if ip in whitelist:
                continue
            if ip in self.rule_names:
                continue

            triggered = False
            reason = ""

            if count >= threshold:
                triggered = True
                reason = f"count={count}"

            if abuse_api_key:
                score = abuseipdb_score(ip, abuse_api_key)
                if score is not None and score >= abuse_min:
                    triggered = True
                    reason += f";abuse_score={score}"

            if triggered:
                self.logger.log("WARN", ip, "THRESHOLD_EXCEEDED", reason)

                subj = f"[DDoS Defender] Umbral excedido - {ip}"
                body = f"La IP {ip} superó threshold.\nRazón: {reason}"

                # Notificaciones
                threading.Thread(
                    target=notify_all_helper,
                    args=(self.cfg, subj, body, "WARN"),
                    daemon=True
                ).start()

                # Si está en modo bloqueo, además bloquea
                if mode == "block":
                    self._block_ip(ip, temp_minutes, silent=True)

    # ------------------------------------------------------------------
    # Firewall / bloqueos
    # ------------------------------------------------------------------
    def _preblock_blacklist(self):
        bl = [
            x.strip() for x in self.cfg.get("GENERAL", "blacklist", "").split(",") if x.strip()
        ]
        if not bl:
            return
        if not is_admin():
            self.logger.log("WARN", "", "PREBLOCK_SKIPPED", "Not admin")
            return

        for ip in bl:
            name = add_firewall_block(ip)
            if name:
                self.rule_names[ip] = name
                self.logger.log("INFO", ip, "PREBLOCK", f"name={name}")
        self._update_block_tab()

    def _block_ip(self, ip, temp_minutes=0, silent=False):
        if not is_admin():
            if not silent:
                messagebox.showerror(
                    "Permiso requerido",
                    "Debes ejecutar la aplicación como Administrador para bloquear IPs."
                )
            return

        if ip in self.rule_names:
            if not silent:
                messagebox.showinfo("Bloqueada", f"IP {ip} ya está bloqueada.")
            return

        name = add_firewall_block(ip)
        if not name:
            if not silent:
                messagebox.showerror("Error", f"No se pudo bloquear {ip}.")
            return

        self.rule_names[ip] = name
        self.logger.log("INFO", ip, "BLOCK", f"name={name};temp={temp_minutes}")
        self.refresh_logs()
        self._update_block_tab()

        if temp_minutes and temp_minutes > 0:
            t = threading.Timer(temp_minutes * 60, lambda: self._auto_unblock(ip))
            t.daemon = True
            t.start()
            self.temp_timers[ip] = t

        if not silent:
            messagebox.showinfo("Bloqueada", f"IP {ip} bloqueada. Regla: {name}")

    def _auto_unblock(self, ip):
        if ip not in self.rule_names:
            return
        name = self.rule_names[ip]
        ok = del_firewall_rule(name)
        if ok:
            self.logger.log("INFO", ip, "AUTO_UNBLOCK", f"name={name}")
            self.rule_names.pop(ip, None)
            self.temp_timers.pop(ip, None)
            self.refresh_logs()
            self._update_block_tab()

    def _unblock_ip(self, ip, silent=False):
        if ip not in self.rule_names:
            if not silent:
                messagebox.showinfo(
                    "Desbloquear",
                    "No se conoce una regla para esa IP (quizá fue bloqueada manualmente)."
                )
            return
        name = self.rule_names[ip]
        ok = del_firewall_rule(name)
        if ok:
            self.logger.log("INFO", ip, "UNBLOCK", f"name={name}")
            self.rule_names.pop(ip, None)
            self.refresh_logs()
            self._update_block_tab()
            if not silent:
                messagebox.showinfo("Desbloqueado", f"IP {ip} desbloqueada.")
        else:
            if not silent:
                messagebox.showerror("Error", f"No se pudo eliminar la regla {name}.")

    def _update_block_tab(self):
        if not hasattr(self, "lst_blocked"):
            return
        self.lst_blocked.delete(0, tk.END)
        for ip in sorted(self.rule_names.keys()):
            self.lst_blocked.insert(tk.END, ip)

    # ------------------------------------------------------------------
    # Handlers GUI
    # ------------------------------------------------------------------
    def open_folder(self):
        path = os.path.abspath(".")
        if sys.platform == "win32":
            subprocess.Popen(f'explorer "{path}"')
        else:
            messagebox.showinfo("Carpeta", path)

    def block_selected(self):
        sel = self.table.selection()
        if not sel:
            messagebox.showwarning("Seleccionar", "Selecciona una IP en la tabla.")
            return
        ip = self.table.item(sel[0])["values"][0]
        try:
            temp = int(self.spin_temp.get())
        except Exception:
            temp = 0
        self._block_ip(ip, temp, silent=False)

    def unblock_selected(self):
        sel = self.table.selection()
        if not sel:
            messagebox.showwarning("Seleccionar", "Selecciona una IP en la tabla.")
            return
        ip = self.table.item(sel[0])["values"][0]
        self._unblock_ip(ip, silent=False)

    def check_selected_abuse(self):
        sel = self.table.selection()
        if not sel:
            messagebox.showwarning("Seleccionar", "Selecciona una IP en la tabla.")
            return
        ip = self.table.item(sel[0])["values"][0]
        api_key = self.entry_abuse_key.get().strip()
        if not api_key:
            messagebox.showinfo("AbuseIPDB", "No hay API key configurada.")
            return
        score = abuseipdb_score(ip, api_key)
        if score is None:
            messagebox.showinfo("AbuseIPDB", f"No se obtuvo respuesta para {ip}.")
        else:
            messagebox.showinfo("AbuseIPDB", f"IP {ip} - abuseConfidenceScore: {score}")

    def unblock_from_tab(self):
        sel = self.lst_blocked.curselection()
        if not sel:
            messagebox.showwarning("Seleccionar", "Selecciona una IP bloqueada.")
            return
        ip = self.lst_blocked.get(sel[0])
        self._unblock_ip(ip, silent=False)

    def manual_block(self):
        ip = self.entry_manual_ip.get().strip()
        if not ip:
            messagebox.showwarning("Manual", "Introduce una IP.")
            return
        try:
            temp = int(self.spin_temp.get())
        except Exception:
            temp = 0
        self._block_ip(ip, temp, silent=False)

    def manual_unblock_by_rule(self):
        name = self.entry_manual_ip.get().strip()
        if not name:
            messagebox.showwarning("Manual", "Introduce el nombre de la regla a eliminar.")
            return
        if not is_admin():
            messagebox.showerror(
                "Permiso requerido",
                "Debes ejecutar la aplicación como Administrador para desbloquear reglas."
            )
            return
        ok = del_firewall_rule(name)
        if ok:
            self.logger.log("INFO", "", "MANUAL_UNBLOCK", f"name={name}")
            messagebox.showinfo("OK", f"Regla {name} eliminada.")
            self.refresh_logs()
        else:
            messagebox.showerror("Error", f"No se pudo eliminar la regla {name}.")

    def refresh_logs(self):
        try:
            conn = sqlite3.connect(self.cfg.get("LOGGING", "log_db", "ddos_defender_logs.db"))
            c = conn.cursor()
            c.execute(
                "SELECT ts, level, ip, action, details FROM events "
                "ORDER BY id DESC LIMIT 200"
            )
            rows = c.fetchall()
            conn.close()
            txt = "\n".join(
                [f"{r[0]} [{r[1]}] {r[2]} {r[3]} {r[4]}" for r in rows]
            )
            if hasattr(self, "txt_logs"):
                self.txt_logs.delete(1.0, tk.END)
                self.txt_logs.insert(tk.END, txt)
        except Exception as e:
            if hasattr(self, "txt_logs"):
                self.txt_logs.delete(1.0, tk.END)
                self.txt_logs.insert(tk.END, f"Error reading logs: {e}")

    # ---------------------- CONTROL MONITOR ----------------------------
    def start_monitor(self):
        if self.monitor is not None and self.monitor.is_alive():
            self.lbl_status.config(text="Estado: Monitoreando...")
            return
        self.stop_event.clear()
        self.monitor = MonitorThread(self.cfg, self.queue, self.stop_event)
        self.monitor.start()
        self.lbl_status.config(text="Estado: Monitoreando...")

    def stop_monitor(self):
        self.stop_event.set()
        self.lbl_status.config(text="Estado: Detenido")

    def stop(self):
        self.stop_event.set()
        # cancel timers
        for t in list(self.temp_timers.values()):
            try:
                t.cancel()
            except Exception:
                pass


# ----------------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------------
def main():
    root = tk.Tk()
    app = App(root)

    def on_close():
        if messagebox.askokcancel("Salir", "¿Deseas salir?"):
            app.stop()
            root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
