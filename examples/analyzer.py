import json
from pathlib import Path

carpeta_proyecto = Path(__file__).resolve().parent
ruta_politica = carpeta_proyecto / "examples" / "broad_policy.json"
with ruta_politica.open(encoding="utf-8") as archivo:
    politica = json.load(archivo)
print("CLOUD IAM POLICY ANALYZER")
print("-------------------------")
for instruccion in politica["Statement"]:
    print("Identificador:", instruccion.get("Sid", "Sin identificador"))
    print("Efecto:", instruccion["Effect"])
    print("Acciones:", instruccion["Action"])
    print("Recursos:", instruccion["Resource"])
    print()
