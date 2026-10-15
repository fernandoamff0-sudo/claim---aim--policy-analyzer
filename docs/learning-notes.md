# Notas de aprendizaje

## Decisiones de implementación

- El analizador usa solo la biblioteca estándar de Python para funcionar sin
  conexión, credenciales de AWS ni instalación de dependencias.
- El análisis, la lectura del archivo y el formato del informe están separados.
  Las pruebas unitarias analizan objetos y las pruebas de terminal ejecutan
  procesos reales.
- La posición de la declaración permite identificarla aunque falte `Sid` o se repita.
- Los comodines son patrones para revisar. Algunas acciones de AWS requieren
  `Resource: "*"`; ese valor no implica automáticamente una vulnerabilidad.
- Las declaraciones `Deny` conservan su efecto y reciben una explicación.
  No se calcula la interacción entre declaraciones que permiten y deniegan.
- Los complementos requieren otra interpretación: `NotAction: "iam:*"` no significa
  que se concedan acciones de IAM. Se solicita una revisión manual.
- El ejemplo original buscaba la política dentro de una carpeta `examples`
  adicional. Ahora localiza el archivo desde la raíz del proyecto y funciona
  independientemente del directorio de trabajo.
- La validación cubre la estructura que requiere el analizador, sin implementar
  toda la gramática de IAM ni un catálogo de acciones por servicio.
- La documentación, las explicaciones y la ayuda se presentan en español.
  Se mantienen los campos oficiales de AWS, las claves JSON y los códigos
  existentes para conservar políticas válidas y compatibilidad con automatizaciones.

## Ejercicios sugeridos

1. Compara los informes de las políticas amplia y específica. Explica qué cambió
   en las acciones y recursos y su relación con el mínimo privilegio.
2. Cambia una copia temporal de `Allow` a `Deny`. Explica por qué el mismo comodín
   tiene un significado diferente para la autorización.
3. Añade una condición y explica por qué evaluarla requiere contexto de la solicitud.
4. Busca una acción de AWS que necesite `Resource: "*"` y documenta la fuente.
5. Añade una prueba antes de ampliar una regla y documenta sus limitaciones.

## Contribuciones personales

Registra aquí tus propios cambios, decisiones, fuentes y conclusiones.
Estas notas se prepararon con asistencia de IA y no acreditan ejercicios
realizados por el propietario del repositorio.
