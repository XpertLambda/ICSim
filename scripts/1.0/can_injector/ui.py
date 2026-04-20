from __future__ import annotations


class UI:
    class C:
        RED     = "\033[91m"
        GREEN   = "\033[92m"
        YELLOW  = "\033[93m"
        BLUE    = "\033[94m"
        MAGENTA = "\033[95m"
        CYAN    = "\033[96m"
        WHITE   = "\033[97m"
        BOLD    = "\033[1m"
        DIM     = "\033[2m"
        RESET   = "\033[0m"

    @staticmethod
    def col(color: str, text) -> str:
        return f"{color}{text}{UI.C.RESET}"

    @staticmethod
    def banner(text: str, color: str | None = None):
        color = color or UI.C.CYAN
        w = 60
        print(f"\n{color}{'═'*w}{UI.C.RESET}")
        print(f"{color}  {text}{UI.C.RESET}")
        print(f"{color}{'═'*w}{UI.C.RESET}")

    @staticmethod
    def section(text: str):
        pad = "─" * max(0, 50 - len(text))
        print(f"\n{UI.C.BOLD}{UI.C.WHITE}── {text} {pad}{UI.C.RESET}")

    @staticmethod
    def ok(t):   print(f"  {UI.col(UI.C.GREEN,  '✔')} {t}")
    @staticmethod
    def warn(t): print(f"  {UI.col(UI.C.YELLOW, '⚠')} {t}")
    @staticmethod
    def err(t):  print(f"  {UI.col(UI.C.RED,    '✘')} {t}")
    @staticmethod
    def info(t): print(f"  {UI.col(UI.C.CYAN,   '→')} {t}")
    @staticmethod
    def dim(t):  print(f"  {UI.col(UI.C.DIM,    '·')} {t}")

    # ── Prompts ───────────────────────────────────────────────────────────────

    @staticmethod
    def prompt(text: str, default=None) -> str | None:
        suffix = f" [{default}]" if default is not None else ""
        try:
            v = input(f"  {UI.C.CYAN}>{UI.C.RESET} {text}{suffix}: ").strip()
        except (KeyboardInterrupt, EOFError):
            return None
        return v if v else (str(default) if default is not None else "")

    @staticmethod
    def prompt_int(text: str, default=None, min_val=None, max_val=None) -> int | None:
        while True:
            raw = UI.prompt(text, default)
            if raw is None:
                return None
            try:
                v = int(raw)
                if min_val is not None and v < min_val:
                    UI.warn(f"Value must be ≥ {min_val}")
                    continue
                if max_val is not None and v > max_val:
                    UI.warn(f"Value must be ≤ {max_val}")
                    continue
                return v
            except ValueError:
                UI.warn("Enter a valid integer.")

    @staticmethod
    def prompt_float(text: str, default=None, min_val=None, max_val=None) -> float | None:
        while True:
            raw = UI.prompt(text, default)
            if raw is None:
                return None
            try:
                v = float(raw)
                if min_val is not None and v < min_val:
                    UI.warn(f"Value must be ≥ {min_val}")
                    continue
                if max_val is not None and v > max_val:
                    UI.warn(f"Value must be ≤ {max_val}")
                    continue
                return v
            except ValueError:
                UI.warn("Enter a valid number.")

    @staticmethod
    def prompt_hex(text: str, default=None) -> int | None:
        while True:
            raw = UI.prompt(text, default)
            if raw is None:
                return None
            try:
                return int(raw, 16)
            except ValueError:
                UI.warn("Enter a valid hex value (e.g. 7E0).")

    @staticmethod
    def prompt_duration() -> float:
        raw = UI.prompt("Duration in seconds (0 = run until stopped)", 0)
        try:
            return max(0.0, float(raw or 0))
        except ValueError:
            return 0.0

    # ── UDS response formatting ───────────────────────────────────────────────

    _NRC: dict[int, str] = {
        0x10: "generalReject",
        0x11: "serviceNotSupported",
        0x12: "subFunctionNotSupported",
        0x13: "incorrectMessageLength",
        0x22: "conditionsNotCorrect",
        0x24: "requestSequenceError",
        0x31: "requestOutOfRange",
        0x33: "securityAccessDenied",
        0x35: "invalidKey",
        0x36: "exceedNumberOfAttempts",
        0x37: "requiredTimeDelayNotExpired",
        0x7E: "subFunctionNotSupportedInSession",
        0x7F: "serviceNotSupportedInSession",
    }

    @staticmethod
    def fmt_nrc(code: int) -> str:
        return f"0x{code:02X} ({UI._NRC.get(code, 'unknown')})"

    @staticmethod
    def print_resp(resp, sid=None):
        if resp is None:
            UI.err("No response (timeout)")
            return
        h = " ".join(f"{b:02X}" for b in resp)
        if len(resp) >= 3 and resp[0] == 0x7F:
            UI.err(f"Negative Response: {h}")
            UI.warn(f"  SID=0x{resp[1]:02X}  NRC={UI.fmt_nrc(resp[2])}")
        else:
            UI.ok(f"Response: {h}")
