# -*- coding: utf-8 -*-
"""
Prueba de concepto (PoC) - Caso 6: SGSI ISO/IEC 27001:2022, Financiera Altiplano S.A. (nombre ficticio)

SUPUESTO TÉCNICO DE MAYOR RIESGO QUE SE VALIDA
  "Con el inventario de fuentes de la entidad, el volumen facturable del SIEM en el nivel analítico
   no supera 30 GB/día y las reglas críticas detectan los ataques con latencia p95 <= 5 minutos
   (reglas casi en tiempo real) aun con un pico de carga de 5 veces el promedio."

QUÉ HACE (tres experimentos)
  E1. Dimensionamiento: genera 20.000 eventos por tipo de fuente con plantillas de formato típicas
      (evento de seguridad de Windows, syslog de firewall, registro W3C de WAF, inicio de sesión del IdP...),
      mide el tamaño medio real de cada uno, calcula GB/día por nivel (analítico / lago de datos)
      y la razón de compresión para el archivo de 1 año.
  E2. Detección: simula 30 minutos de tráfico con la mezcla de fuentes, incluye un pico de 5x durante
      3 minutos e inyecta 70 ataques etiquetados (10 por caso de uso). Un motor de correlación por ventanas
      deslizantes, equivalente a las reglas del SIEM, debe detectarlos. Se miden exhaustividad (recall),
      falsos positivos y eventos por segundo procesados.
  E3. Latencia operativa: para cada detección se suma el retardo de ingesta (supuesto: lognormal con
      mediana 30 s) y la espera de ejecución de la regla (NRT cada 60 s o programada cada 300 s), con
      10.000 réplicas Monte Carlo, y se obtiene la latencia p95 por caso de uso.

LIMITACIONES (se declaran en el documento): valida la lógica de detección y la memoria de cálculo del
dimensionamiento con datos sintéticos; no mide el rendimiento del proveedor SaaS. El tamaño real de los
eventos y el retardo de ingesta se verifican en el paquete EDT 1.6.1.1 con muestreo de 2 semanas.

Uso:  python3 poc_siem.py   -> imprime y escribe resultados_poc.json
"""
import json, random, time, gzip, math, statistics
from collections import defaultdict, deque

random.seed(27001)

# --------------------------------------------------------------------------- Inventario de fuentes
# tipo: (cantidad, EPS por unidad, nivel de destino)  -> nivel "A" = analítico (detección), "L" = lago de datos
FUENTES = {
    "endpoint":        (380, 0.5,  "mixto"),     # 40 % de eventos de seguridad al nivel analítico, resto al lago
    "servidor":        (90,  3.0,  "mixto"),     # 50 % al nivel analítico
    "controlador_dom": (2,   40.0, "A"),
    "ngfw_sede":       (2,   150.0,"mixto"),     # denegaciones y amenazas (10 %) al analítico; permitidas al lago
    "ngfw_sucursal":   (8,   10.0, "mixto"),
    "switch":          (40,  0.5,  "L"),
    "waf":             (1,   100.0,"A"),
    "correo":          (1,   20.0, "A"),
    "base_datos":      (4,   12.5, "A"),
    "idp_mfa":         (1,   40.0, "A"),
    "vpn":             (1,   10.0, "A"),
}
FRACCION_ANALITICA = {"endpoint": 0.40, "servidor": 0.50, "ngfw_sede": 0.10, "ngfw_sucursal": 0.10}
EPS_PROM = sum(n * e for n, e, _ in FUENTES.values())

USUARIOS = [f"u{i:03d}" for i in range(350)]
IPS_INT = [f"10.{s}.{h}.{k}" for s in (10, 20, 30) for h in range(1, 5) for k in range(1, 40)]
DOMINIOS_MALOS = {"secure-login-bank.xyz", "actualiza-datos.co.top", "pago-pendiente.click"}

def ip_ext():
    return f"{random.randint(11,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def guid():
    return "%08x-%04x-%04x-%04x-%012x" % (random.getrandbits(32), random.getrandbits(16), random.getrandbits(16), random.getrandbits(16), random.getrandbits(48))

# --------------------------------------------------------------------------- E1. Plantillas de formato típico
def raw(tipo):
    """Registro crudo con la estructura típica de cada fuente (campos variables aleatorios)."""
    u = random.choice(USUARIOS); h = random.randint(1, 400)
    if tipo in ("endpoint", "servidor", "controlador_dom"):
        eid = random.choice([4624, 4625, 4688, 4663, 4672, 7045])
        return json.dumps({"TimeCreated": "2027-06-15T10:%02d:%02d.%06dZ" % (random.randint(0,59), random.randint(0,59), random.randint(0,999999)),
            "EventID": eid, "Provider": "Microsoft-Windows-Security-Auditing", "Computer": f"{tipo}-{h}.altiplano.local",
            "Channel": "Security", "Keywords": "0x8020000000000000", "Task": random.randint(12000, 13000),
            "SubjectUserSid": "S-1-5-21-%d-%d-%d-%d" % (random.getrandbits(30), random.getrandbits(30), random.getrandbits(30), random.randint(1000, 9999)),
            "SubjectUserName": u, "SubjectDomainName": "ALTIPLANO", "SubjectLogonId": hex(random.getrandbits(32)),
            "TargetUserName": u, "LogonType": random.choice([2, 3, 10]), "IpAddress": random.choice(IPS_INT),
            "ProcessName": random.choice(["C:\\Windows\\System32\\svchost.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                                          "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"]),
            "AuthenticationPackageName": random.choice(["Kerberos", "NTLM", "Negotiate"]), "LogonGuid": "{" + guid() + "}",
            "ActivityID": "{" + guid() + "}", "Opcode": "Info", "Level": "Information"})
    if tipo.startswith("ngfw") or tipo == "switch":
        return ('<189>date=2027-06-15 time=10:%02d:%02d devname="FW-%s" devid="FG2HQ%010d" logid="0000000013" type="traffic" subtype="forward" '
                'level="notice" vd="root" srcip=%s srcport=%d srcintf="port%d" dstip=%s dstport=%d dstintf="wan1" sessionid=%d proto=6 '
                'action="%s" policyid=%d service="HTTPS" duration=%d sentbyte=%d rcvdbyte=%d appcat="unscanned"'
                % (random.randint(0,59), random.randint(0,59), tipo, random.getrandbits(30), random.choice(IPS_INT), random.randint(1024, 65000),
                   random.randint(1, 24), ip_ext(), random.choice([443, 80, 53]), random.getrandbits(31), random.choice(["accept", "close", "deny"]),
                   random.randint(1, 400), random.randint(1, 600), random.randint(100, 90000), random.randint(100, 900000)))
    if tipo == "waf":
        return ("2027-06-15 10:%02d:%02d %s GET /%s - 443 - %s Mozilla/5.0+(Linux;+Android+14)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/126.0+Mobile+Safari/537.36 "
                "https://banca.altiplano.com.co/ %d 0 0 %d %d rule_id=%d ja3=%032x country=CO"
                % (random.randint(0,59), random.randint(0,59), "10.50.0.10", random.choice(["login", "api/saldo", "api/pagos", "api/movimientos?desde=2027-01-01"]),
                   ip_ext(), random.choice([200, 200, 200, 403, 302]), random.randint(200, 9000), random.randint(5, 900), random.randint(0, 999), random.getrandbits(128)))
    if tipo == "correo":
        return json.dumps({"Timestamp": "2027-06-15T10:00:00Z", "NetworkMessageId": guid(), "InternetMessageId": f"<{guid()}@proveedor.com>",
            "SenderFromAddress": f"notificaciones{random.randint(1,999)}@proveedor.com", "RecipientEmailAddress": f"{u}@altiplano.com.co",
            "Subject": random.choice(["Factura pendiente", "Actualización de datos", "Reunión comité"]), "DeliveryAction": "Delivered",
            "ThreatTypes": random.choice(["", "", "Phish", "Spam"]), "AuthenticationDetails": {"SPF": "pass", "DKIM": "pass", "DMARC": "pass"},
            "Urls": [f"https://{random.choice(['proveedor.com', 'docs.example.com'])}/{guid()}"], "AttachmentCount": random.randint(0, 2), "SenderIPv4": ip_ext()})
    if tipo == "base_datos":
        return json.dumps({"event_time": "2027-06-15T10:00:00Z", "action_id": "SL", "succeeded": True, "session_id": random.randint(50, 900),
            "server_principal_name": f"svc_app{random.randint(1,6)}", "database_name": "CORE_CLIENTES", "object_name": random.choice(["clientes", "creditos", "pagos"]),
            "statement": "SELECT id, documento, saldo FROM dbo.clientes WHERE id = @p1", "client_ip": random.choice(IPS_INT), "application_name": "CoreApp", "affected_rows": random.randint(1, 500)})
    if tipo == "idp_mfa":
        return json.dumps({"createdDateTime": "2027-06-15T10:00:00Z", "id": guid(), "userPrincipalName": f"{u}@altiplano.com.co", "appDisplayName": random.choice(["Office 365", "Portal VPN", "Core financiero"]),
            "ipAddress": random.choice(IPS_INT), "clientAppUsed": "Browser", "conditionalAccessStatus": "success", "isInteractive": True,
            "riskLevelDuringSignIn": random.choice(["none", "none", "low"]), "status": {"errorCode": 0, "failureReason": None},
            "deviceDetail": {"deviceId": guid(), "operatingSystem": "Windows 11", "browser": "Edge 126", "isCompliant": True, "trustType": "Hybrid Azure AD joined"},
            "location": {"city": "Bogotá", "state": "Bogotá D.C.", "countryOrRegion": "CO", "geoCoordinates": {"latitude": 4.711, "longitude": -74.072}},
            "authenticationDetails": [{"authenticationMethod": "Password", "succeeded": True}, {"authenticationMethod": random.choice(["Microsoft Authenticator (push)", "FIDO2 security key"]), "succeeded": True}],
            "appliedConditionalAccessPolicies": [{"displayName": "CA01-MFA-todos", "result": "success"}, {"displayName": "CA05-bloqueo-paises", "result": "notApplied"}]})
    if tipo == "vpn":
        return ('<134>%s VPN: user="%s" tunnel="ssl-web" remip=%s assigned_ip=10.99.%d.%d action="tunnel-up" reason="login successful" duration=0 sentbyte=0 rcvdbyte=0 mfa="push"'
                % ("2027-06-15T10:00:00Z", u, ip_ext(), random.randint(0, 255), random.randint(1, 254)))
    raise ValueError(tipo)

def experimento_dimensionamiento(n=20000):
    filas, total_a, total_l = {}, 0.0, 0.0
    muestra_archivo = []
    for tipo, (cant, eps_u, nivel) in FUENTES.items():
        tam = [len(raw(tipo).encode()) + 1 for _ in range(n)]
        b = statistics.mean(tam)
        eps = cant * eps_u
        gb = eps * 86400 * b / 1e9
        frac_a = 1.0 if nivel == "A" else 0.0 if nivel == "L" else FRACCION_ANALITICA[tipo]
        filas[tipo] = {"cantidad": cant, "eps_unidad": eps_u, "eps": eps, "bytes_evento": round(b), "gb_dia": round(gb, 2),
                       "gb_dia_analitico": round(gb * frac_a, 2), "gb_dia_lago": round(gb * (1 - frac_a), 2)}
        total_a += gb * frac_a; total_l += gb * (1 - frac_a)
        muestra_archivo.extend(raw(tipo) for _ in range(max(50, int(2000 * eps / EPS_PROM))))
    datos = "\n".join(muestra_archivo).encode()
    ratio = len(datos) / len(gzip.compress(datos, 6))
    gb_total = total_a + total_l
    return {"por_fuente": filas, "eps_promedio": EPS_PROM, "eps_pico_5x": EPS_PROM * 5,
            "gb_dia_total": round(gb_total, 1), "gb_dia_analitico": round(total_a, 1), "gb_dia_lago": round(total_l, 1),
            "ratio_compresion_gzip": round(ratio, 1),
            "tb_archivo_1_anio_comprimido": round(gb_total * 365 / ratio / 1000, 2),
            "tb_analitico_90_dias": round(total_a * 90 / 1000, 2),
            "mbps_promedio_hacia_nube": round(gb_total * 1e9 * 8 / 86400 / 1e6, 2),
            "mbps_pico_5x": round(gb_total * 1e9 * 8 / 86400 / 1e6 * 5, 2)}

# --------------------------------------------------------------------------- E2. Detección
def evento_normal(ts):
    tipos = list(FUENTES)
    tipo = random.choices(tipos, weights=[FUENTES[t][0] * FUENTES[t][1] for t in tipos])[0]
    u = random.choice(USUARIOS)
    e = {"ts": ts, "src": tipo}
    if tipo in ("idp_mfa", "controlador_dom", "vpn"):
        e.update(evt="login", user=u, result="success" if random.random() > 0.03 else "failure", ip=random.choice(IPS_INT), country="CO")
    elif tipo.startswith("ngfw") or tipo == "switch":
        e.update(evt="conn", src_ip=random.choice(IPS_INT), dst_port=random.choice([443, 443, 80, 53, 25, 3389, 22]),
                 action="deny" if random.random() < 0.05 else "allow")
    elif tipo == "waf":
        e.update(evt="http", path="/login")
    else:
        e.update(evt="otro", user=u)
    return e

def ataque(tipo, t0):
    ev, u, atk_ip = [], random.choice(USUARIOS), ip_ext()
    if tipo == "UC01_fuerza_bruta":            # 15 fallos en 2 minutos y luego éxito
        ev += [{"ts": t0 + i * 8, "src": "idp_mfa", "evt": "login", "user": u, "result": "failure", "ip": atk_ip, "country": "CO"} for i in range(15)]
        ev.append({"ts": t0 + 130, "src": "idp_mfa", "evt": "login", "user": u, "result": "success", "ip": atk_ip, "country": "CO"})
    elif tipo == "UC02_fatiga_mfa":            # 7 solicitudes push rechazadas
        ev += [{"ts": t0 + i * 45, "src": "idp_mfa", "evt": "mfa_push", "user": u, "result": "denied", "ip": atk_ip} for i in range(7)]
    elif tipo == "UC03_viaje_imposible":       # Bogotá y luego otro país 25 minutos después
        ev.append({"ts": t0, "src": "idp_mfa", "evt": "login", "user": u, "result": "success", "ip": random.choice(IPS_INT), "country": "CO"})
        ev.append({"ts": t0 + 1500, "src": "idp_mfa", "evt": "login", "user": u, "result": "success", "ip": atk_ip, "country": "RU"})
    elif tipo == "UC05_clic_phishing":         # navegación a dominio malicioso y login externo 10 minutos después
        ev.append({"ts": t0, "src": "ngfw_sede", "evt": "proxy", "user": u, "domain": random.choice(sorted(DOMINIOS_MALOS))})
        ev.append({"ts": t0 + 600, "src": "idp_mfa", "evt": "login", "user": u, "result": "success", "ip": atk_ip, "country": "CO"})
    elif tipo == "UC09_escaneo":               # 150 puertos distintos en 45 segundos
        ev += [{"ts": t0 + p * 0.3, "src": "ngfw_sede", "evt": "conn", "src_ip": atk_ip, "dst_port": 1000 + p, "action": "deny"} for p in range(150)]
    elif tipo == "UC10_dos":                   # 30.000 solicitudes en 60 s contra /login (5x la línea base del WAF)
        ev += [{"ts": t0 + i * 0.002, "src": "waf", "evt": "http", "path": "/login"} for i in range(30000)]
    elif tipo == "UC13_escalada":              # alta en grupo privilegiado sin ticket de cambio
        ev.append({"ts": t0, "src": "controlador_dom", "evt": "group_add", "user": u, "group": "Domain Admins", "change_ticket": None})
    for e in ev:
        e["_atk"] = (tipo, round(t0, 3))
    return ev

TIPOS = ["UC01_fuerza_bruta", "UC02_fatiga_mfa", "UC03_viaje_imposible", "UC05_clic_phishing", "UC09_escaneo", "UC10_dos", "UC13_escalada"]
NRT = {"UC01_fuerza_bruta", "UC02_fatiga_mfa", "UC09_escaneo", "UC10_dos", "UC13_escalada"}   # reglas casi en tiempo real (cada 60 s)

class Motor:
    """Reglas de correlación con ventanas deslizantes en tiempo de evento."""
    def __init__(self, waf_eps_base):
        self.fail = defaultdict(deque); self.push = defaultdict(deque); self.last = {}
        self.clic = {}; self.ports = defaultdict(deque); self.http = deque(); self.alerts = []
        self.base_min = waf_eps_base * 60; self.dos_activo = False
    def alerta(self, uc, ev):
        self.alerts.append({"uc": uc, "ts": ev["ts"], "atk": ev.get("_atk"), "user": ev.get("user")})
    def procesar(self, ev):
        t, e = ev["ts"], ev["evt"]
        if e == "login":
            u = ev["user"]
            if ev["result"] == "failure":
                q = self.fail[(u, ev["ip"])]; q.append(t)
                while q and t - q[0] > 300: q.popleft()
            else:
                q = self.fail.get((u, ev["ip"]))
                if q and len(q) >= 10:                                       # UC-01
                    self.alerta("UC01_fuerza_bruta", ev); q.clear()
                prev = self.last.get(u)
                if prev and prev[1] != ev["country"] and t - prev[0] < 3600:  # UC-03
                    self.alerta("UC03_viaje_imposible", ev)
                self.last[u] = (t, ev["country"])
                c = self.clic.get(u)
                if c is not None and t - c < 1800 and not ev["ip"].startswith("10."):   # UC-05
                    self.alerta("UC05_clic_phishing", ev); del self.clic[u]
        elif e == "mfa_push" and ev["result"] == "denied":
            q = self.push[ev["user"]]; q.append(t)
            while q and t - q[0] > 600: q.popleft()
            if len(q) >= 5:                                                  # UC-02
                self.alerta("UC02_fatiga_mfa", ev); q.clear()
        elif e == "proxy" and ev["domain"] in DOMINIOS_MALOS:
            self.clic[ev["user"]] = t
        elif e == "conn" and ev["action"] == "deny":
            q = self.ports[ev["src_ip"]]; q.append((t, ev["dst_port"]))
            while q and t - q[0][0] > 60: q.popleft()
            if len({p for _, p in q}) >= 100:                               # UC-09
                self.alerta("UC09_escaneo", ev); q.clear()
        elif e == "http":
            self.http.append((t, ev.get("_atk")))
            while self.http and t - self.http[0][0] > 60: self.http.popleft()
            if not self.dos_activo and len(self.http) > 3 * self.base_min:   # UC-10: > 3x la línea base por minuto
                # la alerta es de volumen: se asocia al ataque presente en la ventana (si lo hay)
                atk = next((x for _, x in reversed(self.http) if x), None)
                self.alerts.append({"uc": "UC10_dos", "ts": t, "atk": atk, "user": None}); self.dos_activo = True
            elif self.dos_activo and len(self.http) < 1.5 * self.base_min:
                self.dos_activo = False
        elif e == "group_add" and ev["group"] in ("Domain Admins", "Enterprise Admins") and not ev["change_ticket"]:
            self.alerta("UC13_escalada", ev)                                 # UC-13

DOS_T = [100, 250, 400, 550, 700, 1160, 1310, 1460, 1610, 1760]

def experimento_deteccion(dur=1900, pico=(900, 1080), factor=5):
    eventos, t = [], 0.0
    while t < dur:
        tasa = EPS_PROM * (factor if pico[0] <= t < pico[1] else 1)
        t += random.expovariate(tasa)
        eventos.append(evento_normal(t))
    ataques = []
    for tipo in TIPOS:
        for k in range(10):
            # los DoS se programan separados entre sí (150 s) y fuera del pico de carga, para medir cada uno por aparte
            t0 = DOS_T[k] if tipo == "UC10_dos" else random.uniform(60, dur - 400)
            ataques.append((tipo, round(t0, 3)))
            eventos.extend(ataque(tipo, t0))
    eventos.sort(key=lambda e: e["ts"])
    m = Motor(FUENTES["waf"][1])
    t1 = time.perf_counter()
    for e in eventos:
        m.procesar(e)
    seg = time.perf_counter() - t1
    det = {a["atk"] for a in m.alerts if a["atk"] and a["atk"][0] == a["uc"]}
    otras = [a for a in m.alerts if not (a["atk"] and a["atk"][0] == a["uc"])]
    usuarios_atacados = {e["user"]: e["ts"] for e in eventos if e.get("_atk") and e.get("user")}
    pico_alertas = [a for a in otras if a["uc"] == "UC10_dos" and pico[0] <= a["ts"] <= pico[1] + 60]
    duplicadas = [a for a in otras if a not in pico_alertas and a["user"] in usuarios_atacados
                  and 0 <= a["ts"] - usuarios_atacados[a["user"]] <= 3600]
    fp = [a for a in otras if a not in pico_alertas and a not in duplicadas]
    por_uc = {tp: {"inyectados": 10, "detectados": sum(1 for d in det if d[0] == tp)} for tp in TIPOS}
    for tp in por_uc:
        por_uc[tp]["recall"] = por_uc[tp]["detectados"] / 10
    return {"duracion_simulada_min": dur / 60, "eventos_procesados": len(eventos), "pico": f"{factor}x durante {(pico[1]-pico[0])/60:.0f} min",
            "eps_procesados_1_nucleo": round(len(eventos) / seg), "segundos_cpu": round(seg, 2),
            "ataques_inyectados": len(ataques), "ataques_detectados": len(det), "recall_global": round(len(det) / len(ataques), 3),
            "alertas_por_pico_de_carga": len(pico_alertas), "alertas_duplicadas_mismo_incidente": len(duplicadas),
            "falsos_positivos": len(fp), "detalle_falsos_positivos": [a["uc"] for a in fp], "por_caso_de_uso": por_uc}, m

# --------------------------------------------------------------------------- E3. Latencia operativa (Monte Carlo)
def experimento_latencia(n=10000, mediana_ingesta=30.0, sigma=0.9):
    res = {}
    for tp in TIPOS:
        intervalo = 60 if tp in NRT else 300
        lat = sorted(random.lognormvariate(math.log(mediana_ingesta), sigma) + random.uniform(0, intervalo) for _ in range(n))
        res[tp] = {"tipo_regla": "NRT (60 s)" if tp in NRT else "programada (300 s)",
                   "p50_s": round(lat[n // 2]), "p95_s": round(lat[int(0.95 * n)]), "cumple_meta": lat[int(0.95 * n)] <= (300 if tp in NRT else 600)}
    return res

def main():
    t0 = time.time()
    e1 = experimento_dimensionamiento()
    e2, _ = experimento_deteccion()
    e3 = experimento_latencia()
    res = {"E1_dimensionamiento": e1, "E2_deteccion": e2, "E3_latencia": e3,
           "conclusion_supuesto": {
               "gb_dia_analitico_<=_30": e1["gb_dia_analitico"] <= 30,
               "recall_>=_0.95": e2["recall_global"] >= 0.95,
               "p95_NRT_<=_300s": all(v["p95_s"] <= 300 for k, v in e3.items() if k in NRT),
               "motor_soporta_pico_5x": e2["eps_procesados_1_nucleo"] >= EPS_PROM * 5},
           "tiempo_total_s": round(time.time() - t0, 1)}
    with open("resultados_poc.json", "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print(json.dumps(res, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
