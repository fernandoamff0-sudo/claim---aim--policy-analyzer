"""Revisión local de patrones en políticas IAM. Sin llamadas a AWS ni dependencias externas."""

import argparse
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import sys


class SpanishHelpFormatter(argparse.HelpFormatter):
    def _format_usage(self, usage, actions, groups, prefix=None):
        return super()._format_usage(usage, actions, groups, prefix or "uso: ")


class SpanishArgumentParser(argparse.ArgumentParser):
    """Ayuda y diagnósticos propios de la interfaz en español."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, add_help=False, formatter_class=SpanishHelpFormatter, **kwargs)
        self._positionals.title = "argumentos posicionales"
        self._optionals.title = "opciones"
        self.add_argument("-h", "--help", action="help", help="Muestra esta ayuda y termina")

    def error(self, message):
        for original, translated in (
            ("the following arguments are required", "faltan los siguientes argumentos obligatorios"),
            ("unrecognized arguments", "argumentos no reconocidos"),
            ("invalid choice", "opción no válida"),
            ("choose from", "elige entre"),
            ("expected one argument", "se esperaba un argumento"),
            ("argument ", "argumento "),
        ):
            message = message.replace(original, translated)
        super().error(message)


class PolicyError(ValueError):
    """La entrada no puede analizarse como un documento de política IAM."""


@dataclass(frozen=True)
class Finding:
    statement: int
    sid: str
    effect: str
    code: str
    field: str
    pattern: str
    message: str
    conditional: bool


def _values(statement, field, index):
    value = statement[field]
    values = [value] if isinstance(value, str) else value
    if not isinstance(values, list) or not values or any(
        not isinstance(item, str) or not item.strip() for item in values
    ):
        raise PolicyError(f"Declaración {index}: {field} debe ser una cadena no vacía o una lista de cadenas no vacías.")
    return values


def validate_policy(policy):
    """Valida la estructura necesaria para la revisión, sin implementar toda la gramática de AWS."""
    if not isinstance(policy, dict):
        raise PolicyError("La política debe ser un objeto JSON.")
    statements = policy.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not statements:
        raise PolicyError("Statement debe ser un objeto o una lista no vacía de objetos.")
    for index, statement in enumerate(statements, 1):
        if not isinstance(statement, dict):
            raise PolicyError(f"La declaración {index} debe ser un objeto.")
        if statement.get("Effect") not in ("Allow", "Deny"):
            raise PolicyError(f"Declaración {index}: Effect debe ser Allow o Deny.")
        if "Sid" in statement and not isinstance(statement["Sid"], str):
            raise PolicyError(f"Declaración {index}: Sid debe ser una cadena.")
        for positive, negative in (("Action", "NotAction"), ("Resource", "NotResource")):
            if (positive in statement) == (negative in statement):
                raise PolicyError(f"Declaración {index}: proporciona exactamente uno de estos campos: {positive} o {negative}.")
            _values(statement, positive if positive in statement else negative, index)
        if "Condition" in statement and not isinstance(statement["Condition"], dict):
            raise PolicyError(f"Declaración {index}: Condition debe ser un objeto.")
    return statements


def analyze_policy(policy):
    """Devuelve hallazgos conservando la identidad y el efecto de cada declaración."""
    findings = []
    for index, statement in enumerate(validate_policy(policy), 1):
        def add(code, field, pattern, message):
            findings.append(Finding(index, statement.get("Sid", "(sin Sid)"),
                                    statement["Effect"], code, field, pattern,
                                    message, bool(statement.get("Condition"))))

        for action in dict.fromkeys(_values(statement, "Action", index) if "Action" in statement else []):
            if action == "*":
                add("ACTION_ALL", "Action", action, "Coincide con todas las acciones; revisa el alcance de la declaración.")
            elif "*" in action or "?" in action:
                add("ACTION_PATTERN", "Action", action, "Patrón de acciones con comodines; revisa todas las acciones que coinciden.")
        if "Resource" in statement and "*" in _values(statement, "Resource", index):
            add("RESOURCE_ALL", "Resource", "*", "Coincide con todos los recursos aplicables; algunas acciones requieren este valor.")
        for field in ("NotAction", "NotResource"):
            if field in statement:
                add("COMPLEMENT_REVIEW", field, ", ".join(_values(statement, field, index)),
                    "Expresión de complemento; revisa manualmente los valores excluidos y el alcance restante.")
    return findings


def load_policy(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        raise PolicyError(f"No se puede leer la política {path}: {exc}") from exc


def format_report(findings):
    lines = ["ANALIZADOR DE POLÍTICAS IAM", "=========================",
             "Este informe identifica patrones para revisar; no determina el acceso efectivo."]
    if not findings:
        lines.append("No se encontraron los patrones buscados. Esto no garantiza que la política sea segura.")
    else:
        lines.append(f"{len(findings)} hallazgo(s) para revisar:")
        for finding in findings:
            lines.extend(["", f"[{finding.code}] Declaración {finding.statement} ({finding.sid}) | {finding.effect}",
                          f"  {finding.field}: {finding.pattern}", f"  {finding.message}"])
            if finding.effect == "Deny":
                lines.append("  Esta declaración tiene efecto Deny (denegación); no concede permisos.")
            if finding.conditional:
                lines.append("  Hay condiciones presentes; no se evalúan.")
    return "\n".join(lines)


def main(argv=None):
    parser = SpanishArgumentParser(description=__doc__)
    parser.add_argument("policy", metavar="politica", type=Path, help="Ruta a un archivo JSON local con una política IAM")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="Formato del informe (predeterminado: text)")
    parser.add_argument("--fail-on-findings", action="store_true", help="Devuelve el código 1 si hay hallazgos para revisar")
    args = parser.parse_args(argv)
    try:
        findings = analyze_policy(load_policy(args.policy))
    except (PolicyError, RecursionError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps({"findings": [asdict(item) for item in findings],
                          "notice": "Solo se identifican patrones para revisar; no se evalúa el acceso efectivo."}, indent=2, ensure_ascii=False))
    else:
        print(format_report(findings))
    return 1 if args.fail_on_findings and findings else 0


if __name__ == "__main__":
    sys.exit(main())
