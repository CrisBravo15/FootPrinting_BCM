# FootPrinting_BCM
Diversos programas que ayudan a realizar FootPrinting a una página web, utilizando técnicas pasivas como DNS(pasivo), whois, tls y tambien haciendo uso de técnicas activas (escaneo de puertos) solo si se tiene el permiso autorizado

# Pasos para la ejecución (script pasivo)
Ejecutar primero el archivo pasivo (No se requiere permiso para realizar)
## Casos de ejecución
- python footprint_bcm.py --target  <host_o_ip>


# Pasos para la ejecución (script activo)
**Advertencia legal y ética:** Ejecutar escaneos de red sin permiso explícito del dueño del host es ilegal en muchos países. No uses este script contra hosts que no te hayan autorizado por escritos

## Requerimientos
- Script principal no requiere paquetes externos.
- Paquetes opcionales (descomentar si los usas):
- python-nmap
- lxml

## Casos de ejecución
- python footprint_activo_bcm.py --target <host_o_ip>

Opciones:
  -t, --target : (requerido) Host o IP a escanear. Ej: tunombre.netlify.app o 1.2.3.4
  -o, --output : (opcional) Ruta del archivo JSON de salida. Si no se indica, el script genera nmap_report_YYYYmmddTHHMMSSZ.json.
