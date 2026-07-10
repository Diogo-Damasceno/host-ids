"""CLI do Host IDS."""

from __future__ import annotations

import argparse
import time

from .engine import take_snapshot, diff

_COLORS = {"critical": "\033[91m", "warning": "\033[93m", "info": "\033[92m"}
_RESET = "\033[0m"


def _print_alert(a, plain=False):
    c = "" if plain else _COLORS.get(a.severity, "")
    r = "" if plain else _RESET
    print(f"{c}[{a.severity.upper():>8}] {a.category:<10} {a.message}{r}")


def main(argv=None):
    p = argparse.ArgumentParser(description="Host IDS — monitora processos, conexões, usuários e integridade.")
    p.add_argument("-i", "--interval", type=float, default=3.0, help="intervalo entre varreduras (s)")
    p.add_argument("-w", "--watch", action="append", default=[],
                   help="arquivo/diretório para checagem de integridade (repetível)")
    p.add_argument("--once", action="store_true", help="uma varredura de baseline e sai")
    p.add_argument("--plain", action="store_true", help="sem cores")
    args = p.parse_args(argv)

    print(f"[*] Host IDS iniciado. Baseline... (watch: {args.watch or 'nenhum'})")
    baseline = take_snapshot(args.watch)
    print(f"[*] Baseline: {len(baseline.processes)} processos, "
          f"{len(baseline.connections)} conexões, {len(baseline.files)} arquivos.")

    if args.once:
        return 0

    print(f"[*] Monitorando a cada {args.interval}s. Ctrl+C para parar.")
    prev = baseline
    try:
        while True:
            time.sleep(args.interval)
            cur = take_snapshot(args.watch)
            for a in diff(prev, cur):
                _print_alert(a, args.plain)
            prev = cur
    except KeyboardInterrupt:
        print("\n[*] Encerrado.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
