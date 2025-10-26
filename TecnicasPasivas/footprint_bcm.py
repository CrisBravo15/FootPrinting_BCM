#!/usr/bin/env python

import logging
import shodan
import os
import getpass
import base64
import stat
import argparse
from datetime import datetime
import json
import socket
import ssl
from pathlib import Path

import dns.resolver
import requests
import whois

# ----------- logs -----------
logging.basicConfig(
    filename='logs.log',              
    level=logging.INFO,              
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# ---------- helpers ----------
def now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def hora():
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

OUTDIR = Path("outputs")
OUTDIR.mkdir(exist_ok=True)

# ----------- shodan -----------
def obtener_api_key():
    ruta = os.path.expanduser("~/.shodan_key")
    if os.path.exists(ruta):
        with open(ruta, "rb") as f:
            encoded = f.read().strip()
        return base64.b64decode(encoded).decode("utf-8")
    else:
        key = getpass.getpass("Ingresa tu Shodan API Key: ")
        encoded = base64.b64encode(key.encode("utf-8"))
        with open(ruta, "wb") as f:
            f.write(encoded)
        try:
            os.chmod(ruta, stat.S_IREAD | stat.S_IWRITE)
        except Exception:
            pass
        logging.info(f"Clave guardada en: {ruta}")
        return key

def summarize_match(m, banner_max=200):
    """
    Extrae solo campos relevantes y truncados:
      - ip, port, transport, product, version, timestamp, country, org
      - banner_snippet (truncado, si existe)
    """
    return {
        "ip": m.get("ip_str"),
        "port": m.get("port"),
        "transport": m.get("transport"),
        "product": m.get("product"),
        "version": m.get("version"),
        "timestamp": m.get("timestamp"),
        "country": m.get("location", {}).get("country_name"),
        "org": m.get("org"),
        "banner_snippet": (m.get("data") or "")[:banner_max] if m.get("data") else None
    }
def run_shodan_search(api, query, limit=50):
    """
    Ejecuta la búsqueda y devuelve dict resumen con total y matches resumidos.
    Limit controla máximo matches añadidos al JSON (no reduce total devuelto por Shodan).
    """
    out = {"query": query, "time": now_iso(), "total": 0, "matches": []}
    try:
        res = api.search(query, page=1)
        out["total"] = res.get("total", 0)
        count = 0
        for m in res.get("matches", []):
            if count >= limit:
                break
            out["matches"].append(summarize_match(m))
            count += 1
    except shodan.APIError as e:
        logging.error(f"Hubo un error con la API: {e}")
        out["error"] = str(e)

    except Exception as e:
        logging.error(f"Hubo un error: {e}")
        out["error"] = str(e)
    return out

def build_query_from_target(target):
    """
    Si target parece IP o CIDR, usa net: or ip:
    Si contiene punto y no es CIDR simple, asume hostname y usa hostname:"..."
    """
    t = target.strip()
    # quick heuristic: CIDR contains '/'
    if '/' in t:
        return f'net:"{t}"'
    # IP simple (only digits and dots)
    parts = t.split('.')
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return f'ip:"{t}"'
    # otherwise hostname
    return f'hostname:"{t}"'



# ---------- DNS ----------
def query_dns(domain):
    resolver = dns.resolver.Resolver()
    out = {}
    for q in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            answers = resolver.resolve(domain, q, lifetime=5)
            # convert to simple strings
            out[q] = [r.to_text().strip() for r in answers]
        except Exception as e:
            out[q] = {"error": str(e)}
    return out

# ---------- WHOIS ----------
def query_whois(domain):
    try:
        w = whois.whois(domain)
        # whois.whois may return objects with non-serializable types; convert carefully
        def safe(v):
            try:
                json.dumps(v)
                return v
            except Exception:
                try:
                    return str(v)
                except Exception:
                    return None
        return {k: safe(v) for k, v in dict(w).items()}
    except Exception as e:
        return {"error": str(e)}

# ---------- subdominios desde crt.sh ----------
def subdomains_from_crtsh(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, timeout=15)
        if r.status_code != 200:
            return {"error": f"crt.sh returned {r.status_code}"}
        data = r.json()
        subs = set()
        for entry in data:
            name = entry.get("name_value", "")
            for n in name.split("\n"):
                n = n.strip()
                if n and n.endswith(domain):
                    subs.add(n)
        subs_list = sorted(subs)
        return {"count": len(subs_list), "subdomains": subs_list}
    except Exception as e:
        return {"error": str(e)}

# ---------- TLS certificado (PEM) ----------
def get_tls_pem(domain, port=443, timeout=6):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                der = ssock.getpeercert(True)
                pem = ssl.DER_cert_to_PEM_cert(der)
                return {"pem": pem}
    except Exception as e:
        return {"error": str(e)}

# ---------- main ----------
def main():
    parser = argparse.ArgumentParser(description="Footprint pasivo con DNS(pasivo),WHOIS, SUBDOMINIOS, TLS, SHODAN")
    parser.add_argument("--target", required=True, help="Dominio objetivo (ej: ejemplo.com)")
    parser.add_argument("--limit", type=int, default=50, help="Max matches to store (default 50)")
    args = parser.parse_args()
    target = args.target.strip()

    api_key = obtener_api_key()
    api = shodan.Shodan(api_key)

    logging.info(f"Iniciando footprint pasivo para: {target}")
    run_ts = now_iso()
    hora_ej = hora()

    # SHODAN
    q = build_query_from_target(target)
    logging.info(f"Ejecutando Shodan query: {q} (limit={args.limit})")
    result = run_shodan_search(api, q, limit=args.limit)

    # DNS
    logging.info("Consultando DNS...")
    dns_res = query_dns(target)

    # WHOIS
    logging.info("Consultando WHOIS/RDAP...")
    whois_res = query_whois(target)
    whois_clean = {k: whois_res.get(k) for k in ("registrar", "creation_date", "expiration_date", "name_servers", "emails")}

    # Subdominios (crt.sh)
    logging.info("Consultando crt.sh para subdominios (pasivo)...")
    crtsh_res = subdomains_from_crtsh(target)

    # TLS (intento de conexión; normalmente pasivo si solo se lee certificado)
    logging.info("Obteniendo certificado TLS (si disponible)...")
    tls_res = get_tls_pem(target)

    # Guardar resultados shodan
    out_path = OUTDIR / f"shodan_{target.replace('/', '_').replace('.', '_')}_{hora_ej}.json"
    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False)

    logging.info(f"Shodan results saved to {out_path}")
    logging.info(f"Total matches (indexadas por Shodan): {result.get('total')}")
    if result.get("total", 0) == 0:
        logging.info("Nota: total==0 indica que Shodan no indexa servicios para este objetivo (baja exposición indexada).")

    # Guardar subdominios por separado si vinieron bien
    subs_json_path = OUTDIR / f"subdominios_{target.replace('.', '_')}_{hora_ej}.json"
    
    if isinstance(crtsh_res, dict) and "subdominios" in crtsh_res:
        with subs_json_path.open("w", encoding="utf-8") as fh:
            json.dump({"target": target, "time": now_iso(), "subdomains": crtsh_res["subdomains"]}, fh, indent=2, ensure_ascii=False)
    else:
        with subs_json_path.open("w", encoding="utf-8") as fh:
            json.dump({"target": target, "time": now_iso(), "result": crtsh_res}, fh, indent=2, ensure_ascii=False)
        logging.error(f"Subdominios: no listados o error. Resultado guardado en {subs_json_path}")

    # Guardar TLS pem si existe
    if isinstance(tls_res, dict) and "pem" in tls_res:
        pem_path = OUTDIR / f"tls_{target.replace('.', '_')}_{hora_ej}.pem"
        with pem_path.open("w", encoding="utf-8") as fh:
            fh.write(tls_res["pem"])
        tls_summary = {"pem_file": str(pem_path), "note": "PEM saved"}
        logging.info(f"Certificado TLS guardado en {pem_path}")
    else:
        tls_summary = {"result": tls_res}
        logging.error(f"[ERROR] TLS: no fue posible obtener PEM o hubo error.")

    # Reporte json total
    report = {
        "metadata": {"target": target, "run_time": run_ts},
        "dns": dns_res,
        "whois": whois_clean,
        "subdomains": crtsh_res,
        "tls": tls_summary
    }

    out_path = OUTDIR / f"reporte_pasivo{target.replace('.', '_')}_{hora_ej}.json"
    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    logging.info(f"Reporte finalizado y guardado en {out_path}")
    print(f"Reporte finalizado y guardado en {out_path}")

if __name__ == "__main__":
    main()
