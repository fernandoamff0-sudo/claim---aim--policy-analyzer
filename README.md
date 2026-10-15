# Analizador de políticas IAM

Herramienta de Python que lee un archivo JSON local con una política de AWS IAM
e identifica patrones de permisos amplios que requieren revisión. Funciona sin
conexión y no necesita cuenta de AWS, credenciales ni paquetes externos.

## Requisitos e inicio rápido

Python 3.10 o superior. Desde la carpeta principal del repositorio:

```bash
python3 analyzer.py examples/broad_policy.json
python3 analyzer.py examples/pattern_policy.json --format json
python3 analyzer.py examples/scoped_policy.json --fail-on-findings
```

El comando original también funciona y utiliza la política amplia incluida:

```bash
python3 examples/analyzer.py
```

Puedes indicar la ruta de cualquier archivo local. Las rutas relativas parten
del directorio actual. Usa `--help` para consultar las opciones en español.
Los archivos se leen en UTF-8 y nunca se modifican.

## Hallazgos

| Código | Patrón | Significado |
| --- | --- | --- |
| `ACTION_ALL` | `Action: "*"` | Coincide con todas las acciones; revisa el alcance. |
| `ACTION_PATTERN` | `s3:*`, `iam:Get*` o patrones con `?` | Revisa las acciones que coinciden con el patrón. |
| `RESOURCE_ALL` | `Resource: "*"` | Coincide con todos los recursos aplicables; algunas acciones requieren este valor. |
| `COMPLEMENT_REVIEW` | `NotAction` o `NotResource` | Revisa manualmente la semántica del complemento. |

Los campos de acciones y recursos admiten cadenas o listas. `Statement` admite
un objeto o una lista no vacía. Cada declaración se identifica por su posición
(desde 1), su `Sid` opcional y su `Effect`. Las acciones duplicadas de una misma
declaración generan un único hallazgo por patrón distinto.

Ejemplo de salida:

```text
[ACTION_ALL] Declaración 1 (BroadPermissions) | Allow
  Action: *
  Coincide con todas las acciones; revisa el alcance de la declaración.
```

La documentación, la ayuda y las explicaciones de los informes están en español.
Los nombres de campos y valores de AWS (`Statement`, `Action`, `Allow`, `Deny`,
etc.) conservan su forma oficial para que las políticas sigan siendo válidas.
También se conservan los nombres de archivos, las opciones de la terminal,
los códigos de hallazgo y las claves JSON para mantener la compatibilidad.

La salida JSON contiene una lista `findings` (hallazgos) y un aviso `notice`.
Cada hallazgo contiene `statement` (posición de la declaración), `sid`
(identificador), `effect` (efecto), `code` (código), `field` (campo), `pattern`
(patrón), `message` (explicación en español) y `conditional` (presencia de
condiciones). Este último indica si hay un objeto `Condition` no vacío;
las condiciones no se evalúan. Los errores se escriben en la salida de errores
estándar, sin generar un informe parcial. Los diagnósticos técnicos del sistema
operativo o del lector JSON pueden conservar el idioma de Python o del sistema.

## Códigos de salida

- `0`: análisis completado; puede haber hallazgos.
- `1`: análisis completado con hallazgos si se indicó `--fail-on-findings`.
- `2`: argumentos inválidos, archivo ilegible, JSON inválido o estructura no admitida.

Por ejemplo, `python3 analyzer.py examples/broad_policy.json --fail-on-findings`
devuelve `1`. Un patrón de `Deny` o un complemento también cuenta como hallazgo;
este código no significa que se haya encontrado una concesión de permisos.

## Alcance y limitaciones

Es una herramienta educativa de revisión de patrones. No implementa toda la
validación de IAM ni simula la autorización de AWS. Un hallazgo invita a revisar
el contexto y no demuestra permisos excesivos. La ausencia de hallazgos no
garantiza que una política sea segura.

- `Allow` (permitir) y `Deny` (denegar) se presentan con su efecto original;
  una denegación amplia no concede permisos.
- Las condiciones de la entrada se conservan, pero no se evalúan.
- `NotAction` y `NotResource` se marcan para revisión manual; no se interpretan
  como listas positivas de acciones o recursos.
- No se evalúan el alcance de los principales, los comodines en ARN de recursos,
  la validez de acciones por servicio, las versiones de políticas, las políticas
  de control de servicios (SCP), los límites de permisos, las políticas de sesión
  ni la interacción entre varias políticas.
- Se exige `Effect`, exactamente uno de `Action`/`NotAction` y exactamente uno de
  `Resource`/`NotResource`. Las políticas fuera de esta estructura se rechazan,
  aunque puedan ser válidas en otro contexto de IAM.

Consulta la documentación de AWS y herramientas adecuadas de autorización para
tomar decisiones de acceso reales. Evita publicar políticas con datos sensibles.

## Desarrollo y pruebas

```bash
python3 -m unittest discover -s tests -v
```

Las pruebas cubren detecciones, validación de entrada, condiciones, denegaciones,
complementos, formatos de salida, códigos de salida y el comando de ejemplo.
También comprueban que la ayuda y los mensajes principales estén en español.
GitHub Actions está configurado para Python 3.10 y 3.12.

```text
analyzer.py                  Funciones de análisis e interfaz de terminal
examples/analyzer.py         Punto de entrada compatible con el comando original
examples/broad_policy.json   Ejemplo de todas las acciones y recursos
examples/pattern_policy.json Patrones por servicio, condiciones y denegación
examples/scoped_policy.json  Acción y recurso específicos
tests/test_analyzer.py       Pruebas con la biblioteca estándar
docs/learning-notes.md       Decisiones y ejercicios de aprendizaje
```

## Proceso de desarrollo

Desarrollado con asistencia de IA. Consulta las [notas de aprendizaje](docs/learning-notes.md)
para conocer las decisiones y ejercicios. Las contribuciones y conclusiones
personales deben registrarse por quien las realizó; las notas generadas no
atribuyen ejercicios completados al propietario del repositorio.
