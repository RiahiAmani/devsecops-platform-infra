#!/usr/bin/env python3
"""
Générateur de dashboard HTML lisible à partir des rapports JSON
de kube-bench (CIS Benchmark) et kube-hunter (test d'intrusion).
"""
import argparse
import json
import html
import re  # Requis pour nettoyer les sauts de lignes et espaces multiples
from datetime import datetime
from pathlib import Path
from string import Template

# ---------- Lecture ----------
def load_json(path):
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        print(f"[!] Fichier introuvable, ignoré : {path}")
        return None
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Erreur de lecture/parsing JSON pour {path} : {e}")
        return None

# ---------- Parsing kube-bench ----------
def parse_kube_bench(data):
    if data is None:
        return None
    stats = {"PASS": 0, "FAIL": 0, "WARN": 0, "INFO": 0}
    fails = []

    def walk(node):
        if isinstance(node, dict):
            if "status" in node and ("test_desc" in node or "test_number" in node):
                status = str(node.get("status", "")).upper()
                if status in stats:
                    stats[status] += 1
                if status == "FAIL" or status == "WARN":  
                    rem_raw = node.get("remediation", "") or ""
                    rem_html = "<br>".join([html.escape(line.strip()) for line in rem_raw.split("\n") if line.strip()])
                    
                    fails.append({
                        "id": node.get("test_number", "?"),
                        "status": status,
                        "desc": node.get("test_desc", "").strip(),
                        "remediation": rem_html,
                    })
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(data)
    total = sum(stats.values())
    if total == 0:
        return None
    return {"stats": stats, "fails": fails, "total": total}

# Kube-hunter stocke le texte descriptif des services dans le docstring Python
# de chaque classe (visible uniquement dans le rendu texte du terminal), et ne
# l'exporte PAS dans le rapport JSON. On restitue donc ici les descriptions
# officielles des services les plus couramment détectés, en repli.
KNOWN_SERVICE_DESCRIPTIONS = {
    "Kubelet API": "Le Kubelet est le composant principal de chaque nœud : toutes les opérations sur les pods transitent par lui.",
    "Etcd": "Etcd est la base de données qui stocke l'état du cluster ; elle contient la configuration et peut contenir des secrets.",
    "API Server": "L'API Server est en charge de l'ensemble des opérations effectuées sur le cluster.",
    "Kubernetes Dashboard": "Interface web d'administration du cluster Kubernetes.",
    "Kube Proxy": "Le Kube Proxy gère les règles réseau permettant la communication entre les pods et les services.",
    "kubectl proxy exposed": "Un kubectl proxy exposé publiquement peut donner accès complet à l'API du cluster.",
}

# ---------- Parsing kube-hunter ----------
def parse_kube_hunter(data):
    if data is None:
        return None
    services = data.get("services", []) or []
    vulnerabilities = data.get("vulnerabilities", []) or []

    # Fonction de nettoyage pour recoller les lignes coupées et supprimer les doubles espaces
    def clean_text(text):
        if not text:
            return ""
        text = text.replace("\n", " ").replace("\r", " ").replace("\t", " ")
        return re.sub(r'\s+', ' ', text).strip()

    norm_services = []
    for s in services:
        name = s.get("service") or "?"
        # Ordre de priorité : description du JSON -> dictionnaire de repli connu -> message par défaut
        desc_brute = s.get("description") or KNOWN_SERVICE_DESCRIPTIONS.get(name) or "Aucune description disponible."

        norm_services.append({
            "service": name,
            "location": s.get("location", "?"),
            "description": clean_text(desc_brute),
        })

    norm_vulns = []
    for v in vulnerabilities:
        sev = (v.get("severity") or "medium").lower()
        norm_vulns.append({
            "vid": v.get("vid") or v.get("id") or "?",
            "location": v.get("location", "?"),
            "name": v.get("vulnerability") or v.get("name") or "?",
            "description": clean_text(v.get("description")),
            "evidence": v.get("evidence", ""),
            "severity": sev,
        })

    return {"services": norm_services, "vulnerabilities": norm_vulns}

# ---------- Rendu HTML ----------
SEVERITY_COLOR = {
    "low": ("warn", "Faible"),
    "medium": ("warn", "Moyenne"),
    "high": ("risk", "Élevée"),
    "critical": ("risk", "Critique"),
}

def esc(s):
    return html.escape(str(s), quote=True)

def render_bench_section(bench):
    if bench is None:
        return '<section><h2>kube-bench</h2><p class="muted">Aucune donnée disponible.</p></section>'
    s = bench["stats"]
    total = bench["total"]
    fails_html = ""
    
    if bench["fails"]:
        rows = ""
        for f in bench["fails"]:
            status_class = "pill warn" if f['status'] == "WARN" else "pill risk"
            rows += f"""
            <tr>
              <td class="code">{esc(f['id'])}</td>
              <td><span class="{status_class}">{f['status']}</span></td>
              <td>{esc(f['desc'])}</td>
              <td class="remediation-block">{f['remediation'] or '—'}</td>
            </tr>"""
        fails_html = f"""
        <h3>Contrôles non conformes ou à vérifier ({len(bench['fails'])})</h3>
        <div class="scroll-panel" style="max-height: 400px; overflow-y: auto; border: 1px solid var(--border); border-radius: 6px;">
            <table>
              <thead><tr><th>ID</th><th>Statut</th><th>Contrôle</th><th>Remédiation / Commandes</th></tr></thead>
              <tbody>{rows}</tbody>
            </table>
        </div>"""
    else:
        fails_html = '<div class="banner ok"><b>Aucun échec</b><p>Tous les contrôles automatisés sont conformes au CIS Benchmark.</p></div>'

    return f"""
  <section>
    <h2>kube-bench <span class="tag tool">CIS Kubernetes Benchmark</span></h2>
    <p class="sub">{total} contrôles évalués au total.</p>
    <div class="stats">
      <div class="stat pass"><div class="label">Conformes</div><div class="value">{s['PASS']}</div></div>
      <div class="stat fail"><div class="label">Non conformes</div><div class="value">{s['FAIL']}</div></div>
      <div class="stat warn"><div class="label">Avertissements</div><div class="value">{s['WARN']}</div></div>
      <div class="stat"><div class="label">Informatifs</div><div class="value" style="color:var(--muted)">{s['INFO']}</div></div>
    </div>
    {fails_html}
  </section>
"""

def render_hunter_section(hunter):
    if hunter is None:
        return '<section><h2>kube-hunter</h2><p class="muted">Aucune donnée disponible.</p></section>'
    
    services_rows = ""
    for s in hunter["services"]:
        services_rows += f"""<tr>
            <td><strong>{esc(s['service'])}</strong></td>
            <td class="code">{esc(s['location'])}</td>
            <td>{esc(s['description'])}</td>
        </tr>"""

    vulns_rows = ""
    if hunter["vulnerabilities"]:
        for v in hunter["vulnerabilities"]:
            pill_class, pill_label = SEVERITY_COLOR.get(v["severity"], ("warn", v["severity"].title()))
            evidence_str = f' <br><span class="code" style="color:var(--green)">Evidence: {esc(v["evidence"])}</span>' if v['evidence'] else ''
            vulns_rows += f"""
            <tr>
              <td><b>{esc(v['vid'])}</b> — {esc(v['name'])}</td>
              <td>{esc(v['location'])}</td>
              <td><span class="pill {pill_class}">{esc(pill_label)}</span></td>
              <td>{esc(v['description'])}{evidence_str}</td>
            </tr>"""
        vulns_block = f"""
        <table>
          <thead><tr><th>Vulnérabilité</th><th>Emplacement</th><th>Gravité</th><th>Détail</th></tr></thead>
          <tbody>{vulns_rows}</tbody>
        </table>"""
    else:
        vulns_block = '<div class="banner ok"><b>Aucune vulnérabilité détectée</b><p>Le scan de pénétration n\'a identifié aucun point exploitable direct.</p></div>'

    return f"""
  <section>
    <h2>kube-hunter <span class="tag tool">Test d'intrusion</span></h2>
    <p class="sub">{len(hunter['services'])} service(s) détecté(s) — {len(hunter['vulnerabilities'])} vulnérabilité(s) trouvée(s).</p>
    <div class="grid-2">
      <div>
        <h3>Services exposés ({len(hunter['services'])})</h3>
        <table>
          <thead><tr><th>Service</th><th>Adresse</th><th>Description</th></tr></thead>
          <tbody>{services_rows}</tbody>
        </table>
      </div>
      <div>
        <h3>Vulnérabilités Détectées</h3>
        {vulns_block}
      </div>
    </div>
  </section>
"""

# Template HTML
PAGE_TEMPLATE = Template("""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Dashboard d'audit de sécurité — Cluster Kubernetes</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700;800&display=swap');
  :root {
    --bg:#0F1626; --panel:#17223A; --panel-2:#1D2B47; --border:#2A3B57;
    --text:#E7EEF7; --muted:#8FA3C0; --cyan:#38BDF8;
    --green:#34D399; --amber:#FBBF24; --red:#F87171;
    --mono:'IBM Plex Mono',monospace; --sans:'Inter',sans-serif;
  }
  * {box-sizing:border-box;}
  body {
    margin:0;
    background:
      radial-gradient(1200px 500px at 15% -10%, rgba(56,189,248,0.10), transparent 60%),
      radial-gradient(900px 500px at 100% 0%, rgba(52,211,153,0.06), transparent 55%),
      var(--bg);
    color:var(--text); font-family:var(--sans); padding:36px 28px 60px;
  }
  .wrap {max-width:1180px;margin:0 auto;}
  header {margin-bottom:28px;}
  .eyebrow {font-size:12px;letter-spacing:.12em;color:var(--cyan);text-transform:uppercase;margin:0 0 10px;}
  h1 {font-size:28px;font-weight:600;margin:0 0 6px;letter-spacing:-0.01em;}
  .meta {color:var(--muted);font-size:14px;margin:0;}
  .scanline {height:2px;margin-top:22px;border-radius:2px;
    background:linear-gradient(90deg, var(--cyan) 0%, rgba(56,189,248,0) 35%, rgba(52,211,153,0.6) 70%, rgba(52,211,153,0) 100%);
    background-size:200% 100%; animation:sweep 3.5s linear infinite;}
  @keyframes sweep {0% {background-position:0% 0;} 100% {background-position:-200% 0;}}
  .stats {display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:18px 0 26px;}
  .stat {background:var(--panel-2);border:1px solid var(--border);border-radius:10px;padding:16px 16px 14px;}
  .stat .label {font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px;}
  .stat .value {font-size:30px;font-weight:600;line-height:1;}
  .stat.pass .value {color:var(--green);} .stat.fail .value {color:var(--red);} .stat.warn .value {color:var(--amber);}
  section {background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:26px 28px 30px;margin-bottom:24px;}
  section h2 {font-size:18px;margin:0 0 4px;display:flex;align-items:center;gap:10px;}
  section h3 {font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin:15px 0 10px;}
  section .sub {color:var(--muted);font-size:13.5px;margin:0 0 18px;}
  .tag {font-size:11px;letter-spacing:.06em;padding:2px 8px;border-radius:5px;text-transform:uppercase;
    background:rgba(56,189,248,0.12);color:var(--cyan);border:1px solid rgba(56,189,248,0.35);}
  .grid-2 {display:grid;grid-template-columns:1fr 1.3fr;gap:26px;}
  @media (max-width:880px) { .grid-2 {grid-template-columns:1fr;} .stats {grid-template-columns:repeat(2,1fr);} }
  table {width:100%;border-collapse:collapse;font-size:13px;}
  th {text-align:left;font-size:10.5px;letter-spacing:.05em;color:var(--muted);text-transform:uppercase;padding:8px 10px;border-bottom:1px solid var(--border);}
  td {padding:9px 10px;border-bottom:1px solid rgba(255,255,255,0.05);vertical-align:top;}
  .code {font-family:var(--mono);font-size:12px;color:var(--cyan);}
  .muted {color:var(--muted);}
  .remediation-block {font-family:var(--mono); font-size:11px; color:#A7F3D0; background: rgba(16, 185, 129, 0.05); border-radius: 4px; padding: 4px;}
  .pill {font-size:10.5px;font-weight:600;padding:3px 9px;border-radius:20px;display:inline-block;white-space:nowrap;}
  .pill.warn {background:rgba(251,191,36,0.15);color:var(--amber);border:1px solid rgba(251,191,36,0.4);}
  .pill.risk {background:rgba(248,113,113,0.12);color:var(--red);border:1px solid rgba(248,113,113,0.35);}
  .banner {border-radius:10px;padding:14px 16px;margin-top:6px;background:rgba(251,191,36,0.08);border:1px solid rgba(251,191,36,0.3);}
  .banner.ok {background:rgba(52,211,153,0.08);border-color:rgba(52,211,153,0.3);}
  .banner b {font-size:11.5px;text-transform:uppercase;letter-spacing:.04em;}
  .banner.ok b {color:var(--green);}
  .banner p {margin:6px 0 0;font-size:13px;color:var(--text);line-height:1.5;}
  footer {color:var(--muted);font-size:12px;text-align:center;margin-top:30px;}

  /* Scrollbar sombre cohérente avec le thème (tableau des non-conformités) */
  .scroll-panel::-webkit-scrollbar { width: 8px; height: 8px; }
  .scroll-panel::-webkit-scrollbar-track { background: var(--panel-2); border-radius: 6px; }
  .scroll-panel::-webkit-scrollbar-thumb { background: var(--border); border-radius: 6px; }
  .scroll-panel::-webkit-scrollbar-thumb:hover { background: var(--cyan); }
  .scroll-panel { scrollbar-width: thin; scrollbar-color: var(--border) var(--panel-2); }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>Cluster Kubernetes · devsecops-lab</h1>
    <p class="meta">Généré le $generated_at</p>
    <div class="scanline"></div>
  </header>
  $bench_section
  $hunter_section
  <footer>Fichier produit dynamiquement à partir des API JSON de kube-bench et kube-hunter</footer>
</div>
</body>
</html>""")

def main():
    ap = argparse.ArgumentParser(description="Génère un dashboard HTML lisible depuis kube-bench/kube-hunter (JSON).")
    ap.add_argument("--bench", help="Chemin du rapport JSON kube-bench", default=None)
    ap.add_argument("--hunter", help="Chemin du rapport JSON kube-hunter", default=None)
    ap.add_argument("--output", help="Fichier HTML de sortie", default="dashboard.html")
    args = ap.parse_args()

    bench_raw = load_json(args.bench)
    hunter_raw = load_json(args.hunter)

    bench = parse_kube_bench(bench_raw)
    hunter = parse_kube_hunter(hunter_raw)

    if bench is None and hunter is None:
        print("[!] Aucune donnée exploitable trouvée dans les fichiers fournis. Fin d'exécution.")
        return

    html_out = PAGE_TEMPLATE.substitute(
        generated_at=datetime.now().strftime("%d/%m/%Y à %H:%M"),
        bench_section=render_bench_section(bench),
        hunter_section=render_hunter_section(hunter),
    )
    Path(args.output).write_text(html_out, encoding="utf-8")
    print(f"[OK] Dashboard généré avec succès dans : {args.output}")

if __name__ == "__main__":
    main()
