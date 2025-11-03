"""
footprint_activo_bcm.py

Versión sencilla: ejecuta `nmap -Pn -F -sV` (escaneo rápido de puertos comunes),
parsea lo mínimo de la salida XML y guarda un JSON.

Uso:
    python3 footprint_activo_bcm.py --target tunombre.netlify.app
    python3 footprint_activo_bcm.py -t 1.2.3.4 -o reporte.json

Requiere: nmap instalado y accesible en PATH.
"""

import argparse
import subprocess
import sys
import xml.etree.ElementTree as ET
import json
from datetime import datetime
from pathlib import Path
import shutil

def ensure_nmap():
    if shutil.which("nmap") is None:
        print("Error: nmap no está instalado o no está en PATH.", file=sys.stderr)
        sys.exit(2)

def run_nmap_xml(target):
    # Escaneo rápido: -Pn (no ping), -F (fast - puertos comunes), -sV (detectar servicio), -oX - (xml stdout)
    cmd = [
        "nmap",
        "-Pn",
        "-F",
        "-sV",
        "-oX", "-",   # XML -> stdout
        target
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return proc.stdout
    except subprocess.CalledProcessError as e:
        print("Error: nmap falló con código", e.returncode, file=sys.stderr)
        if e.stdout:
            print("stdout:", e.stdout, file=sys.stderr)
        if e.stderr:
            print("stderr:", e.stderr, file=sys.stderr)
        sys.exit(3)

def parse_minimal(xml_text):
    root = ET.fromstring(xml_text)
    result = {
        "scanned_at": datetime.utcnow().isoformat() + "Z",
        "hosts": []
    }
    for host in root.findall("host"):
        h = {"addresses": [], "hostnames": [], "ports": []}
        # addresses
        for addr in host.findall("address"):
            h["addresses"].append({
                "addr": addr.attrib.get("addr"),
                "type": addr.attrib.get("addrtype")
            })
        # hostnames
        for hn in host.findall("hostnames/hostname"):
            name = hn.attrib.get("name")
            if name:
                h["hostnames"].append(name)
        # ports
        ports = host.find("ports")
        if ports is not None:
            for p in ports.findall("port"):
                portid = p.attrib.get("portid")
                proto = p.attrib.get("protocol")
                state_el = p.find("state")
                svc_el = p.find("service")
                port_obj = {
                    "port": int(portid) if portid and portid.isdigit() else portid,
                    "protocol": proto,
                    "state": state_el.attrib.get("state") if state_el is not None else None,
                    "service": svc_el.attrib.get("name") if svc_el is not None else None
                }
                h["ports"].append(port_obj)
        result["hosts"].append(h)
    return result

def save_json(data, outpath=None):
    if outpath is None:
        outpath = f"nmap_report_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.json"
    p = Path(outpath)
    p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return str(p.resolve())

def main():
    parser = argparse.ArgumentParser(description="Run nmap -F and save a simple JSON report.")
    parser.add_argument("-t", "--target", required=True, help="Host o IP a escanear")
    parser.add_argument("-o", "--output", help="Archivo JSON de salida (opcional)")
    args = parser.parse_args()


    # COMPROBACION DE PERMISOS
    print("Antes de ejecutar este código debes de tener autorización de la persona o institución a la que realices este escaneo ya que el escaneo es invasivo para los servidores")
    
    autorizacion = input("¿Tienes el permiso de la persona a cargo? [Si/No]")

    if autorizacion.lower() == "si":
        nombre = input("Ingresa tu nombre para el registro: ")
        cadena = nombre + ", " + autorizacion.lower() + ", " + args.target + ", " + str(datetime.now())
        ruta = r"C:\registro.txt"

        import os

        # Crea archivo con la respuesta de si tiene permiso o no
        with open(ruta, "a", encoding="utf-8") as f:
            f.write(cadena + "\n") 

        # Oculta el archivo para que el usuario no lo pueda borrar
        os.system(f'attrib +h "{ruta}"')
    else:
        print("No se tiene el permiso necesario para ejecutar este script")
        sys.exit()

    ensure_nmap()
    print("Ejecutando nmap -F (scan rápido de puertos comunes)...")
    xml = run_nmap_xml(args.target)
    print("Parseando resultado...")
    parsed = parse_minimal(xml)
    parsed_meta = {
        "target": args.target,
        "nmap_opts": {"flags": ["-Pn", "-F", "-sV"]}
    }
    out = {"meta": parsed_meta, "report": parsed}
    saved = save_json(out, args.output)
    print("Reporte guardado en:", saved)

if __name__ == "__main__":
    main()
