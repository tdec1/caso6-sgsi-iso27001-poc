"""Simulación de la encuesta del Anexo C (n=64). DATOS SIMULADOS con IA, autorizado por el docente.
Reproducible: python3 encuesta_simulada.py  (semilla 27001). Salida: respuestas_simuladas.csv y resultados_encuesta.json"""
import random, json, csv, statistics as st
random.seed(27001)
N = 64
def ch(opts, w): return random.choices(opts, weights=w)[0]
rows = []
for i in range(1, N + 1):
    cargo = ch(["Atención al público", "Administrativo", "Técnico (TI)", "Directivo", "No aplica"], [34, 36, 18, 6, 6])
    r = {"id": i, "P1": "Sí" if cargo != "No aplica" else ch(["Sí", "No"], [20, 80]), "P2": ch(["18-25", "26-35", "36-45", "46-55", ">55"], [22, 40, 24, 11, 3]), "P3": cargo}
    exp = {"Atención al público": [10, 35, 40, 15], "Administrativo": [12, 40, 35, 13], "Técnico (TI)": [8, 42, 38, 12], "Directivo": [10, 45, 35, 10], "No aplica": [25, 45, 22, 8]}[cargo]
    r["P4"] = ch(["Nunca", "Mensual", "Semanal", "Diaria"], exp)
    clic = {"Atención al público": [28, 62, 10], "Administrativo": [22, 68, 10], "Técnico (TI)": [12, 78, 10], "Directivo": [20, 68, 12], "No aplica": [20, 68, 12]}[cargo]
    r["P5"] = ch(["Sí", "No", "No sé"], clic)
    rep = {"Atención al público": [38, 62], "Administrativo": [52, 48], "Técnico (TI)": [88, 12], "Directivo": [60, 40], "No aplica": [45, 55]}[cargo]
    r["P6"] = ch(["Sí", "No"], rep)
    r["P7"] = ch(["Nunca", "Alguna vez", "Con frecuencia"], [58, 33, 9])
    r["P8"] = ch(["Sí", "No", "Algunas"], [30, 28, 42])
    r["P9"] = ch(["Sí, en ambos", "Solo banco", "Solo trabajo", "No"], [30, 42, 8, 20])
    base = 3.9 if r["P9"] != "No" else 3.3
    r["P10"] = min(5, max(1, round(random.gauss(base, 0.95))))
    r["P11"] = ch(["Notificación con número", "Código SMS", "Llave física", "Huella o rostro", "Ninguno"], [34, 18, 8, 36, 4])
    r["P12"] = ch(["Sí", "No", "Solo si la empresa lo provee"], [60, 12, 28])
    r["P13"] = min(5, max(1, round(random.gauss(3.7 if r["P3"] != "Técnico (TI)" else 4.3, 0.95))))
    r["P14"] = ch(["0", "1-2", "3-5", ">5"], [32, 40, 20, 8])
    r["P15"] = ch(["Video corto", "Taller presencial", "Simulación", "Lectura"], [40, 18, 32, 10])
    r["P16"] = ch(["Sí", "Depende", "No, por temor a sanción"], [55, 28, 17])
    r["P17"] = min(5, max(1, round(random.gauss(3.2, 1.1))))
    r["P18"] = ch(["Procesos más simples", "Capacitación corta y frecuente", "Un botón único para reportar", "Menos contraseñas", "Reconocimiento y no sanción"], [22, 26, 24, 16, 12])
    rows.append(r)
with open("respuestas_simuladas.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
pct = lambda k, v: round(100 * sum(1 for r in rows if (r[k] in v if isinstance(v, (list, tuple)) else r[k] == v)) / N, 1)
mean = lambda k: round(st.mean(r[k] for r in rows), 2)
res = {"n": N, "P4_semanal_o_mas": pct("P4", ["Semanal", "Diaria"]), "P5_clic": pct("P5", "Sí"), "P6_sabe_reportar": pct("P6", "Sí"),
       "P9_mfa_actual": pct("P9", ["Sí, en ambos", "Solo banco", "Solo trabajo"]), "P10_media": mean("P10"), "P10_4_o_5": pct("P10", [4, 5]) if False else round(100*sum(1 for r in rows if r["P10"]>=4)/N,1),
       "P12_no_o_condicion": pct("P12", ["No", "Solo si la empresa lo provee"]), "P12_no": pct("P12", "No"), "P13_media": mean("P13"),
       "P16_inmediato": pct("P16", "Sí"), "P16_temor": pct("P16", "No, por temor a sanción"), "P17_media": mean("P17"), "P17_4_o_5": round(100*sum(1 for r in rows if r["P17"]>=4)/N,1),
       "P7_comparte": pct("P7", ["Alguna vez", "Con frecuencia"]), "P8_repite": pct("P8", ["Sí", "Algunas"]), "P14_cero": pct("P14", "0"),
       "P11_num": pct("P11", "Notificación con número"), "P11_bio": pct("P11", "Huella o rostro"), "P11_sms": pct("P11", "Código SMS"), "P11_llave": pct("P11", "Llave física"),
       "P15_video": pct("P15", "Video corto"), "P15_sim": pct("P15", "Simulación"),
       "P5_sucursal": round(100*sum(1 for r in rows if r["P3"]=="Atención al público" and r["P5"]=="Sí")/max(1,sum(1 for r in rows if r["P3"]=="Atención al público")),1),
       "P6_sucursal": round(100*sum(1 for r in rows if r["P3"]=="Atención al público" and r["P6"]=="Sí")/max(1,sum(1 for r in rows if r["P3"]=="Atención al público")),1),
       "n_sucursal": sum(1 for r in rows if r["P3"]=="Atención al público"),
       "P4_sucursal": round(100*sum(1 for r in rows if r["P3"]=="Atención al público" and r["P4"] in ("Semanal","Diaria"))/max(1,sum(1 for r in rows if r["P3"]=="Atención al público")),1),
       "P6_tec": round(100*sum(1 for r in rows if r["P3"]=="Técnico (TI)" and r["P6"]=="Sí")/max(1,sum(1 for r in rows if r["P3"]=="Técnico (TI)")),1),
       "n_tec": sum(1 for r in rows if r["P3"]=="Técnico (TI)"),
       "P1_si": pct("P1", "Sí")}
json.dump(res, open("resultados_encuesta.json", "w"), ensure_ascii=False, indent=1)
print(json.dumps(res, ensure_ascii=False, indent=1))
