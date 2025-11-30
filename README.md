
# 🛡 DDoS Defender Pro – Enterprise Edition

Monitor de conexiones TCP en tiempo real, firewall automático inteligente, logging avanzado, alertas por múltiples canales y herramientas de análisis de red integradas en GUI. Ideal para proteger VPS, servidores Windows, gateways, home servers, hosting, paneles de juegos y más.

🚨 Bloqueo automático  
📝 Registro persistente SQLite  
📡 Webhooks (Email, Telegram, Discord)  
🛠 Tab avanzado de herramientas de red  
⚙ Configuración completa vía interfaz  
💾 Sin dependencias externas de pago  

---

## 📍 Imagenes

![Preview](https://github.com/Azzlaer/Firewall_DDoS_PRO/blob/main/img/1.png)
![Preview](https://github.com/Azzlaer/Firewall_DDoS_PRO/blob/main/img/2.png)
![Preview](https://github.com/Azzlaer/Firewall_DDoS_PRO/blob/main/img/3.png)
![Preview](https://github.com/Azzlaer/Firewall_DDoS_PRO/blob/main/img/4.png)
![Preview](https://github.com/Azzlaer/Firewall_DDoS_PRO/blob/main/img/5.png)
![Preview](https://github.com/Azzlaer/Firewall_DDoS_PRO/blob/main/img/6.png)
![Preview](https://github.com/Azzlaer/Firewall_DDoS_PRO/blob/main/img/7.png)

---

## 📍 Características principales

| Módulo | Función |
|---|---|
| 📊 Dashboard | Monitor completo de conexiones en tiempo real + gráfico histórico |
| 🚫 Firewall & Bloqueos | Gestión de reglas firewall, bloqueos temporales o permanentes |
| 📝 Logs | Registro histórico en SQLite + log-file tradicional |
| 📡 Webhooks & Alertas | Notificación automática ante ataques / Auto-block events |
| ⚙ Sistema & Reglas | Configuración persistente guardada en `config.ini` |
| 🛠 Herramientas | WHOIS Lookup – Reverse DNS – Ping – GeoIP Lookup |

---

## 🏗 Requisitos

| Software | Necesario para |
|---|---|
| Windows (con permisos Admin) | Netsh firewall rules |
| Python 3.8+ | Proyecto base |
| psutil | Monitor TCP real-time |
| requests | API AbuseIPDB y GeoIP |
| matplotlib | Gráfica en Dashboard |
| sqlite3 (incluido en Python) | Base de datos de eventos |
| whois (opcional) | WHOIS Lookup en Tab Tools |

Instala dependencias:

```bash
pip install psutil requests matplotlib
```

---

## 📦 Ejecución

```bash
python main.py
```

---

## 📄 Créditos

Creado por:

✦ ChatGPT OpenAI  
✦ Azzlaer  
✦ Para LatinBattle.com
