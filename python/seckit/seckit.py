#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
╔══════════════════════════════════════════════════════════════════════════════╗
║ ██████╗ ██╗      ██████╗██╗  ██╗███████╗███╗   ██╗ █████╗ ██╗  ██╗███████╗   ║
║ ██╔══██╗██║     ██╔════╝██║ ██╔╝██╔════╝████╗  ██║██╔══██╗██║ ██╔╝██╔════╝   ║
║ ██████╔╝██║     ██║     █████╔╝ ███████╗██╔██╗ ██║███████║█████╔╝ █████╗     ║
║ ██╔══██╗██║     ██║     ██╔═██╗ ╚════██║██║╚██╗██║██╔══██║██╔═██╗ ██╔══╝     ║
║ ██████╔╝███████╗╚██████╗██║  ██╗███████║██║ ╚████║██║  ██║██║  ██╗███████╗   ║
║ ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝   ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ SCRIPT:    seckit.py                                                         ║
║ AUTHOR:    Jeysson Rostran                                                   ║
║ DATE:      2026-09-11                                                        ║
║ VERSION:   1.3.0                                                             ║
║ PURPOSE:   All-in-one desktop security and cryptography toolkit              ║
║ LICENSE:   MIT                                                               ║
║                                                                              ║
║ RESOURCES:                                                                   ║
║   - https://github.com/blcksnake/Tools/tree/main/python/seckit                           ║
║   - https://blcksnake.com                                                    ║
║                                                                              ║
║ CHANGELOG:                                                                   ║
║   v1.3.0 [2026-09-11] - Portable build and Python 3.14/Tcl 9 support         ║
║   v1.2.0              - Added usernames, certificates, and appearance modes  ║
║   v1.0.0              - Initial security toolkit release                     ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ SECKIT FEATURES:                                                             ║
║   - Strong password and secure username generation                           ║
║   - Random tokens plus text and file hashing                                 ║
║   - JWT encoding, decoding, and signature verification                       ║
║   - RSA, EC, Ed25519, and OpenSSH key-pair generation                        ║
║   - X.509 root CAs, CSRs, certificate signing, and verification              ║
║   - Certificate details, SANs, fingerprints, and expiration                  ║
║   - Dark, light, and system themes with opt-in anonymous analytics           ║
║                                                                              ║
║ INSTALL:   pip install customtkinter cryptography PyJWT                      ║
║ RUN:       python seckit.py                                                  ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import customtkinter as ctk
from tkinter import filedialog, messagebox
import secrets
import string
import hashlib
import base64
import json
import datetime
import threading
import math
import ipaddress
import sys
import platform
import urllib.request
import uuid
from pathlib import Path

# Required third-party crypto packages. The except branch raises, so past this
# block every imported name is guaranteed bound to the real module.
try:
    import jwt as pyjwt
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, padding
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.exceptions import InvalidSignature
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
except ImportError as exc:
    raise SystemExit(
        "SecKit needs cryptography and PyJWT (plus customtkinter for the GUI):\n"
        "    pip install customtkinter cryptography PyJWT\n"
        f"(import error: {exc})"
    )


ctk.set_appearance_mode("dark")

# ---- BLCKSNAKE brand Colors ----
# Primary yellows: #FDB913 / #FFDE2F   Neutrals: #000000 / #E6E7E8
# Secondary navy:  #001E3A / #001628
BRAND_YELLOW = "#FDB913"
BRAND_YELLOW_LT = "#FFDE2F"
BRAND_BLACK = "#000000"
BRAND_NAVY = "#001E3A"
BRAND_NAVY_DEEP = "#001628"
BRAND_GREY = "#E6E7E8"

ACCENT = BRAND_YELLOW
ACCENT_HOVER = BRAND_YELLOW_LT
ACCENT_TEXT = BRAND_BLACK
DANGER = "#f87171"
WARN = "#fbbf24"
OK = "#34d399"
MUTED = ("#6B6E72", "#A8ABB0")
GREY_BTN = ("#CFD0D2", BRAND_NAVY)
GREY_HOVER = ("#B0B2B5", "#00284D")
# theme-aware (light, dark) tuples so text stays readable in both modes
IDLE_TEXT = (BRAND_NAVY_DEEP, BRAND_GREY)
ON_ACCENT_TEXT = BRAND_BLACK

# standard field widths so every form lines up the same way
W_FIELD = 220
W_SHORT = 90
W_WIDE = 460

# ---- app / developer / analytics config ----
APP_VERSION = "1.3.0"
DEV_NAME = "BLCKSNAKE"
AUTHOR_NAME = "Jeysson Rostran"
DEV_EMAIL = "info@blcksnake.com"
DEV_SITE = "https://blcksnake.com"
# Where opt-in analytics are POSTed. Point this at your own server; if it's blank
# analytics are disabled entirely regardless of the user's choice.
ANALYTICS_ENDPOINT = "https://analytics.blcksnake.com/collect"
ANALYTICS_API_KEY = "blk_live_lq-la1IvE0lTBkd4NCqJkOVjx9m_29GGee0cABAl9aY"
CONFIG_DIR = Path.home() / ".seckit"
CONFIG_FILE = CONFIG_DIR / "config.json"


def resource_dir():
    """Directory that holds bundled assets (works for script + frozen builds)."""
    if getattr(sys, "frozen", False):
        # PyInstaller onefile/onedir both expose _MEIPASS for bundled data.
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            base = Path(meipass)
            if (base / "assets").is_dir():
                return base
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


ASSETS_DIR = resource_dir() / "assets"
THEME_PATH = ASSETS_DIR / "blcksnake.json"
LOGO_PATH = ASSETS_DIR / "blcksnake-logo.png"
LOGO_SIDEBAR_PATH = ASSETS_DIR / "logo-sidebar.png"
LOGO_ABOUT_PATH = ASSETS_DIR / "logo-about.png"
ICON_PATH = ASSETS_DIR / "seckit.ico"

if THEME_PATH.is_file():
    ctk.set_default_color_theme(str(THEME_PATH))
else:
    ctk.set_default_color_theme("blue")

def _pil_open(path):
    """Lazy Pillow open so the GUI still starts if Pillow is missing."""
    from PIL import Image
    return Image.open(path)


# pick brand / mono fonts that actually exist
try:
    import tkinter.font as tkfont
    _families = {f.lower(): f for f in tkfont.families()}

    def _pick(*names, fallback="Segoe UI"):
        for name in names:
            if name.lower() in _families:
                return _families[name.lower()]
        return fallback

    UI_FONT = _pick("Montserrat", "Segoe UI", "Arial")
    TITLE_FONT = _pick("Cubadak", "Montserrat", "Segoe UI", "Arial")
    if "jetbrains mono" in _families:
        MONO = (_families["jetbrains mono"], 12)
    elif "consolas" in _families:
        MONO = ("Consolas", 12)
    else:
        MONO = ("Courier", 12)
except Exception:
    UI_FONT = "Segoe UI"
    TITLE_FONT = "Segoe UI"
    MONO = ("Courier", 12)


# ---------- crypto helpers ----------
def priv_encryption(passphrase):
    """Return a PEM encryption algorithm; encrypt only if a passphrase is given."""
    if passphrase:
        return serialization.BestAvailableEncryption(passphrase.encode())
    return serialization.NoEncryption()


def load_private_key(pem_text, passphrase):
    pw = passphrase.encode() if passphrase else None
    return serialization.load_pem_private_key(pem_text.strip().encode(), password=pw)


def make_key(kind):
    """kind like 'RSA 2048', 'EC P-256', 'Ed25519' -> private key object."""
    if kind.startswith("RSA"):
        return rsa.generate_private_key(public_exponent=65537, key_size=int(kind.split()[1]))
    if kind.startswith("EC"):
        curve = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(),
                 "P-521": ec.SECP521R1()}[kind.split()[1]]
        return ec.generate_private_key(curve)
    return ed25519.Ed25519PrivateKey.generate()


def sign_hash_for(key):
    """Ed25519 signs without a separate hash; everything else uses SHA-256."""
    return None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()


def key_to_pem(key, passphrase, fmt=None):
    """Serialize a private key to PEM. fmt defaults to PKCS8."""
    fmt = fmt or serialization.PrivateFormat.PKCS8
    return key.private_bytes(serialization.Encoding.PEM, fmt,
                             priv_encryption(passphrase)).decode()


def describe_public_key(pub):
    if isinstance(pub, rsa.RSAPublicKey):
        return f"RSA {pub.key_size}-bit"
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"EC {pub.curve.name}"
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519"
    return type(pub).__name__


def san_objects(items):
    """Turn a list of strings into DNSName / IPAddress SAN objects, de-duplicated."""
    out, seen = [], set()
    for item in items:
        item = item.strip()
        if not item or item in seen:
            continue
        seen.add(item)
        try:
            out.append(x509.IPAddress(ipaddress.ip_address(item)))
        except ValueError:
            out.append(x509.DNSName(item))
    return out


def split_csv(text):
    """Split a comma-separated string into stripped, non-empty parts."""
    return [s.strip() for s in text.split(",") if s.strip()]


def verify_cert_signature(cert, issuer_pub):
    """Raise InvalidSignature if cert was NOT signed by the issuer's public key."""
    if isinstance(issuer_pub, rsa.RSAPublicKey):
        issuer_pub.verify(cert.signature, cert.tbs_certificate_bytes,
                          padding.PKCS1v15(), cert.signature_hash_algorithm)
    elif isinstance(issuer_pub, ec.EllipticCurvePublicKey):
        issuer_pub.verify(cert.signature, cert.tbs_certificate_bytes,
                          ec.ECDSA(cert.signature_hash_algorithm))
    elif isinstance(issuer_pub, ed25519.Ed25519PublicKey):
        issuer_pub.verify(cert.signature, cert.tbs_certificate_bytes)
    else:
        raise InvalidSignature("Unsupported CA key type for verification")


def cert_validity_window(c):
    """Return (not_before, not_after) as tz-aware UTC, across cryptography versions."""
    try:
        return c.not_valid_before_utc, c.not_valid_after_utc
    except AttributeError:
        utc = datetime.timezone.utc
        return (c.not_valid_before.replace(tzinfo=utc),
                c.not_valid_after.replace(tzinfo=utc))


def name_values(name):
    """Comma-joined attribute values of an x509.Name, safely stringified."""
    return ", ".join(str(a.value) for a in name)


def to_int(text, default):
    try:
        return int(text)
    except ValueError:
        return default


def shuffle_chars(chars):
    """Fisher–Yates shuffle using the CSPRNG."""
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return chars


# Curated word pools for readable usernames (no ambiguous look-alikes like "one"/"l").
_USERNAME_ADJECTIVES = (
    "amber", "aqua", "bold", "brave", "bright", "brisk", "calm", "cedar",
    "clear", "clever", "coral", "crisp", "cyber", "daring", "delta", "eager",
    "ember", "fast", "flint", "focal", "frost", "gentle", "glad", "golden",
    "grand", "green", "happy", "harbor", "hidden", "ivory", "jade", "keen",
    "kind", "laser", "lunar", "maple", "merry", "mint", "noble", "nova",
    "ocean", "olive", "orbit", "pearl", "plaid", "plucky", "prime", "proud",
    "pulse", "quick", "quiet", "rapid", "river", "rocky", "royal", "sable",
    "safe", "sharp", "silent", "silver", "sleek", "solar", "solid", "sonic",
    "spark", "steel", "storm", "swift", "tidal", "tiger", "ultra", "urban",
    "vapor", "vivid", "warm", "wild", "wise", "zenith",
)

_USERNAME_NOUNS = (
    "anchor", "apex", "arrow", "atlas", "badge", "beacon", "blade", "blaze",
    "bolt", "bridge", "byte", "canyon", "castle", "cipher", "comet", "coral",
    "crane", "crest", "crown", "delta", "dragon", "drift", "eagle", "ember",
    "falcon", "field", "flame", "flare", "forge", "forest", "fox", "galaxy",
    "glider", "grove", "harbor", "hawk", "horizon", "island", "jewel", "kite",
    "knight", "lake", "lance", "leaf", "lotus", "lynx", "meadow", "meteor",
    "mirror", "mountain", "nebula", "nexus", "oak", "orbit", "otter", "panda",
    "phoenix", "pilot", "pixel", "plume", "portal", "prism", "quest", "quill",
    "raven", "ridge", "river", "rocket", "rover", "saber", "sage", "scout",
    "shadow", "shard", "shield", "signal", "sparrow", "sphere", "sprite",
    "summit", "talon", "thunder", "tiger", "torch", "tower", "vector", "voyage",
    "wave", "willow", "wolf", "zenith",
)

_PRONOUNCE_CONS = "bcdfghjklmnpqrstvwxz"
_PRONOUNCE_VOWELS = "aeiou"


def generate_secure_username(style, length=12, digits=4, separator="_",
                             lowercase=True, no_ambiguous=True, prefix=""):
    """Build one username with the CSPRNG. Styles mirror the Username panel options."""
    ambig = set("0O1lI")
    digit_alphabet = string.digits
    alnum = string.ascii_lowercase + string.digits
    if no_ambiguous:
        digit_alphabet = "".join(ch for ch in digit_alphabet if ch not in ambig)
        alnum = "".join(ch for ch in alnum if ch not in ambig)

    def digit_tail(n):
        if n <= 0:
            return ""
        return "".join(secrets.choice(digit_alphabet) for _ in range(n))

    prefix = "".join(ch for ch in prefix.strip() if ch.isalnum() or ch in "_-.")
    sep = separator if separator in ("_", "-", ".") else ""

    if style.startswith("Word pair"):
        adj = secrets.choice(_USERNAME_ADJECTIVES)
        noun = secrets.choice(_USERNAME_NOUNS)
        while noun == adj:
            noun = secrets.choice(_USERNAME_NOUNS)
        core = f"{adj}{sep}{noun}" if sep else f"{adj}{noun}"
        name = f"{core}{sep}{digit_tail(digits)}" if digits else core
    elif style.startswith("CamelCase"):
        adj = secrets.choice(_USERNAME_ADJECTIVES).capitalize()
        noun = secrets.choice(_USERNAME_NOUNS).capitalize()
        name = f"{adj}{noun}{digit_tail(digits)}"
        lowercase = False  # camelCase is the point
    elif style.startswith("Random alphanumeric"):
        length = max(4, min(64, length))
        # always start with a letter so it is a valid handle on most sites
        letters = string.ascii_lowercase
        if no_ambiguous:
            letters = "".join(ch for ch in letters if ch not in ambig)
        first = secrets.choice(letters)
        rest = "".join(secrets.choice(alnum) for _ in range(length - 1))
        name = first + rest
    elif style.startswith("Pronounceable"):
        length = max(4, min(64, length))
        parts = []
        while len("".join(parts)) < length:
            parts.append(secrets.choice(_PRONOUNCE_CONS))
            parts.append(secrets.choice(_PRONOUNCE_VOWELS))
        name = "".join(parts)[:length]
        if digits:
            name = f"{name}{digit_tail(digits)}"
    else:  # Hex token
        nbytes = max(2, min(32, (length + 1) // 2))
        name = secrets.token_hex(nbytes)
        if prefix:
            name = f"{prefix}{sep}{name}" if sep else f"{prefix}{name}"
            prefix = ""  # already applied

    if prefix and not style.startswith("Hex"):
        name = f"{prefix}{sep}{name}" if sep else f"{prefix}{name}"
    if lowercase:
        name = name.lower()
    return name


# ---------- reusable widgets & helpers ----------
class FormGrid(ctk.CTkFrame):
    """A left-aligned label+field grid with a trailing spacer column, so fields
    keep a natural fixed width instead of stretching edge-to-edge at any window size."""
    def __init__(self, master, spacer_col=4, **kw):
        super().__init__(master, fg_color="transparent", **kw)
        self.grid_columnconfigure(spacer_col, weight=1)

    def field(self, row, col, label, default="", width=W_FIELD, span=1):
        ctk.CTkLabel(self, text=label).grid(row=row, column=col, sticky="w", padx=(0, 8), pady=4)
        entry = ctk.CTkEntry(self, width=width)
        if default:
            entry.insert(0, default)
        entry.grid(row=row, column=col + 1, columnspan=span, sticky="w", padx=(0, 24), pady=4)
        return entry

    def option(self, row, col, label, values):
        ctk.CTkLabel(self, text=label).grid(row=row, column=col, sticky="w", padx=(0, 8), pady=4)
        menu = ctk.CTkOptionMenu(self, values=values)
        menu.grid(row=row, column=col + 1, sticky="w", padx=(0, 24), pady=4)
        return menu


class OutputBox(ctk.CTkFrame):
    """A read-friendly text output with Copy + Clear + optional Save."""
    def __init__(self, master, height=180, save_cb=None, **kw):
        super().__init__(master, fg_color="transparent", **kw)
        self.grid_columnconfigure(0, weight=1)
        self.box = ctk.CTkTextbox(self, height=height, font=MONO, wrap="word")
        self.box.grid(row=0, column=0, columnspan=3, sticky="nsew", pady=(0, 6))
        self.grid_rowconfigure(0, weight=1)
        self.copy_btn = ctk.CTkButton(self, text="Copy", width=90, command=self._copy)
        self.copy_btn.grid(row=1, column=0, sticky="w")
        ctk.CTkButton(self, text="Clear", width=90, fg_color=GREY_BTN,
                      hover_color=GREY_HOVER, text_color=IDLE_TEXT,
                      command=self.clear).grid(row=1, column=1, padx=6, sticky="w")
        if save_cb:
            ctk.CTkButton(self, text="Save…", width=90, command=save_cb).grid(row=1, column=2, sticky="w")

    def set(self, text):
        self.box.delete("1.0", "end")
        self.box.insert("1.0", text)

    def get(self):
        return self.box.get("1.0", "end").strip()

    def clear(self):
        self.box.delete("1.0", "end")

    def _copy(self):
        txt = self.get()
        if txt:
            self.clipboard_clear()
            self.clipboard_append(txt)
            self.copy_btn.configure(text="Copied!")
            self.after(1200, lambda: self.copy_btn.configure(text="Copy"))


def section_title(master, text):
    return ctk.CTkLabel(master, text=text, font=(TITLE_FONT, 22, "bold"),
                        text_color=(BRAND_NAVY_DEEP, BRAND_YELLOW), anchor="w")


def accent_button(master, text, command, **kw):
    """Primary CTA — brand yellow with black label for WCAG contrast."""
    opts = {"text": text, "command": command, "fg_color": ACCENT,
            "hover_color": ACCENT_HOVER, "text_color": ACCENT_TEXT}
    opts.update(kw)
    return ctk.CTkButton(master, **opts)


def grey_button(master, text, command, height=None):
    kw = {"text": text, "command": command, "fg_color": GREY_BTN,
          "hover_color": GREY_HOVER, "text_color": IDLE_TEXT}
    if height:
        kw["height"] = height
    return ctk.CTkButton(master, **kw)


def passphrase_row(master, label="Passphrase (optional):"):
    """A labeled masked entry with a show/hide toggle. Returns (frame, entry)."""
    frame = ctk.CTkFrame(master, fg_color="transparent")
    ctk.CTkLabel(frame, text=label).grid(row=0, column=0, padx=(0, 8))
    entry = ctk.CTkEntry(frame, width=240, show="•")
    entry.grid(row=0, column=1)

    def toggle():
        entry.configure(show="" if entry.cget("show") else "•")

    ctk.CTkButton(frame, text="show", width=54, fg_color=GREY_BTN,
                  hover_color=GREY_HOVER, text_color=IDLE_TEXT, command=toggle).grid(
        row=0, column=2, padx=8)
    return frame, entry


def save_text_dialog(content, default_name, filetypes):
    if not content:
        messagebox.showwarning("Nothing to save", "Generate something first.")
        return
    path = filedialog.asksaveasfilename(defaultextension="",
                                        initialfile=default_name,
                                        filetypes=filetypes)
    if path:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        messagebox.showinfo("Saved", f"Written to:\n{path}")


def load_text_into(box, title="Choose a PEM file"):
    path = filedialog.askopenfilename(title=title)
    if not path:
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            box.set(f.read())
    except OSError as err:
        messagebox.showerror("Read error", str(err))


def run_async(root, work, done):
    """Run a slow function off the UI thread, then call done(result, error) on the UI thread.

    A broad catch is intentional here: this is a thread boundary and any exception
    from `work` must be marshaled back to the UI rather than killing the worker.
    """
    def worker():
        try:
            res = work()
            root.after(0, lambda: done(res, None))
        except Exception as err:  # noqa: BLE001 - deliberate thread-boundary catch
            root.after(0, lambda captured=err: done(None, captured))
    threading.Thread(target=worker, daemon=True).start()


def run_task(app, btn, idle_text, work, on_success, error_title="Error", busy_text="Working…"):
    """Disable a button, run `work` in the background, then either call
    on_success(result) or pop an error dialog — restoring the button either way."""
    btn.configure(text=busy_text, state="disabled")

    def done(res, err):
        btn.configure(text=idle_text, state="normal")
        if err:
            messagebox.showerror(error_title, str(err))
            return
        on_success(res)

    run_async(app, work, done)


def save_button(box, name, filetypes):
    """A Save… callback bound to an OutputBox's current contents."""
    return lambda: save_text_dialog(box.get(), name, filetypes)


PEM_FILES = [("PEM", "*.pem"), ("All", "*.*")]
CERT_FILES = [("Cert", "*.crt *.pem"), ("All", "*.*")]
KEY_FILES = [("Key", "*.key *.pem"), ("All", "*.*")]


# ---------- panels ----------
class PasswordPanel(ctk.CTkScrollableFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self.grid_columnconfigure(0, weight=1)
        section_title(self, "Password Generator").grid(row=0, column=0, sticky="w", pady=(0, 14))

        self.len_var = ctk.IntVar(value=20)
        self.len_label = ctk.CTkLabel(self, text="Length: 20")
        self.len_label.grid(row=1, column=0, sticky="w")
        ctk.CTkSlider(self, from_=6, to=128, number_of_steps=122,
                      command=self._len_changed, variable=self.len_var).grid(
            row=2, column=0, sticky="ew", pady=(0, 12))

        opts = ctk.CTkFrame(self, fg_color="transparent")
        opts.grid(row=3, column=0, sticky="w", pady=(0, 12))
        self.lower = ctk.CTkCheckBox(opts, text="a-z"); self.lower.select()
        self.upper = ctk.CTkCheckBox(opts, text="A-Z"); self.upper.select()
        self.digits = ctk.CTkCheckBox(opts, text="0-9"); self.digits.select()
        self.symbols = ctk.CTkCheckBox(opts, text="!@#$%…"); self.symbols.select()
        self.noambig = ctk.CTkCheckBox(opts, text="No look-alikes (0/O l/1)")
        for i, w in enumerate((self.lower, self.upper, self.digits, self.symbols, self.noambig)):
            w.grid(row=0, column=i, padx=(0, 16))

        cnt = ctk.CTkFrame(self, fg_color="transparent")
        cnt.grid(row=4, column=0, sticky="w", pady=(0, 12))
        ctk.CTkLabel(cnt, text="How many:").grid(row=0, column=0, padx=(0, 8))
        self.count = ctk.CTkEntry(cnt, width=70); self.count.insert(0, "1")
        self.count.grid(row=0, column=1)
        ctk.CTkButton(cnt, text="Generate", command=self.generate,
                      fg_color=ACCENT, hover_color=ACCENT_HOVER, text_color=ACCENT_TEXT).grid(row=0, column=2, padx=12)

        self.strength = ctk.CTkLabel(self, text="", anchor="w")
        self.strength.grid(row=5, column=0, sticky="w", pady=(0, 6))

        self.out = OutputBox(self, height=200, save_cb=lambda: save_text_dialog(
            self.out.get(), "passwords.txt", [("Text", "*.txt"), ("All", "*.*")]))
        self.out.grid(row=6, column=0, sticky="nsew")
        self.grid_rowconfigure(6, weight=1)

    def _len_changed(self, _):
        self.len_label.configure(text=f"Length: {self.len_var.get()}")

    def generate(self):
        ambiguous = "0O1lI|`'\""
        classes = []
        if self.lower.get():   classes.append(string.ascii_lowercase)
        if self.upper.get():   classes.append(string.ascii_uppercase)
        if self.digits.get():  classes.append(string.digits)
        if self.symbols.get(): classes.append("!@#$%^&*()-_=+[]{};:,.<>?/")
        if self.noambig.get():
            classes = ["".join(ch for ch in cls if ch not in ambiguous) for cls in classes]
        classes = [c for c in classes if c]  # drop any class emptied by the filter
        if not classes:
            messagebox.showwarning("Pick a set", "Select at least one character set.")
            return
        pool = "".join(classes)
        length = self.len_var.get()
        if length < len(classes):
            messagebox.showwarning(
                "Too short",
                f"Length must be at least {len(classes)} to include every selected set.")
            return
        n = max(1, min(100, to_int(self.count.get(), 1)))

        def one():
            # guarantee at least one char from each selected class, then fill the rest
            chars = [secrets.choice(cls) for cls in classes]
            chars += [secrets.choice(pool) for _ in range(length - len(classes))]
            return "".join(shuffle_chars(chars))

        self.out.set("\n".join(one() for _ in range(n)))
        entropy = length * math.log2(len(pool))
        rating = ("Weak" if entropy < 50 else "Fair" if entropy < 80
                  else "Strong" if entropy < 120 else "Excellent")
        self.strength.configure(text=f"~{entropy:.0f} bits of entropy  •  {rating}  (pool size {len(pool)})")


class UsernamePanel(ctk.CTkScrollableFrame):
    """Secure usernames that are hard to guess but still usable as handles."""
    STYLES = [
        "Word pair + digits",
        "CamelCase + digits",
        "Random alphanumeric",
        "Pronounceable",
        "Hex token",
    ]

    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self.grid_columnconfigure(0, weight=1)
        section_title(self, "Secure Usernames").grid(row=0, column=0, sticky="w", pady=(0, 6))
        ctk.CTkLabel(
            self,
            text="CSPRNG-backed handles for accounts, bots, and throwaway identities.",
            text_color=MUTED, anchor="w").grid(row=1, column=0, sticky="w", pady=(0, 14))

        form = FormGrid(self, spacer_col=6)
        form.grid(row=2, column=0, sticky="ew", pady=(0, 8))
        self.style = form.option(0, 0, "Style:", self.STYLES)
        self.style.set(self.STYLES[0])

        self.len_var = ctk.IntVar(value=12)
        self.len_label = ctk.CTkLabel(self, text="Length (random / pronounceable / hex): 12")
        self.len_label.grid(row=3, column=0, sticky="w")
        ctk.CTkSlider(self, from_=6, to=32, number_of_steps=26,
                      command=self._len_changed, variable=self.len_var).grid(
            row=4, column=0, sticky="ew", pady=(0, 12))

        opts = ctk.CTkFrame(self, fg_color="transparent")
        opts.grid(row=5, column=0, sticky="w", pady=(0, 12))
        self.lowercase = ctk.CTkCheckBox(opts, text="Lowercase"); self.lowercase.select()
        self.noambig = ctk.CTkCheckBox(opts, text="No look-alikes (0/O l/1)"); self.noambig.select()
        self.lowercase.grid(row=0, column=0, padx=(0, 16))
        self.noambig.grid(row=0, column=1, padx=(0, 16))

        row = ctk.CTkFrame(self, fg_color="transparent")
        row.grid(row=6, column=0, sticky="w", pady=(0, 12))
        ctk.CTkLabel(row, text="Digit suffix:").grid(row=0, column=0, padx=(0, 8))
        self.digits = ctk.CTkEntry(row, width=60); self.digits.insert(0, "4")
        self.digits.grid(row=0, column=1)
        ctk.CTkLabel(row, text="Separator:").grid(row=0, column=2, padx=(16, 8))
        self.sep = ctk.CTkOptionMenu(row, values=["_", "-", ".", "(none)"], width=90)
        self.sep.grid(row=0, column=3)
        ctk.CTkLabel(row, text="Prefix:").grid(row=0, column=4, padx=(16, 8))
        self.prefix = ctk.CTkEntry(row, width=100, placeholder_text="optional")
        self.prefix.grid(row=0, column=5)
        ctk.CTkLabel(row, text="How many:").grid(row=0, column=6, padx=(16, 8))
        self.count = ctk.CTkEntry(row, width=60); self.count.insert(0, "10")
        self.count.grid(row=0, column=7)
        ctk.CTkButton(row, text="Generate", command=self.generate,
                      fg_color=ACCENT, hover_color=ACCENT_HOVER, text_color=ACCENT_TEXT).grid(row=0, column=8, padx=12)

        self.info = ctk.CTkLabel(self, text="", anchor="w", text_color=MUTED)
        self.info.grid(row=7, column=0, sticky="w", pady=(0, 6))

        self.out = OutputBox(self, height=260, save_cb=lambda: save_text_dialog(
            self.out.get(), "usernames.txt", [("Text", "*.txt"), ("All", "*.*")]))
        self.out.grid(row=8, column=0, sticky="nsew")
        self.grid_rowconfigure(8, weight=1)

    def _len_changed(self, _):
        self.len_label.configure(
            text=f"Length (random / pronounceable / hex): {self.len_var.get()}")

    def generate(self):
        style = self.style.get()
        length = self.len_var.get()
        digits = max(0, min(12, to_int(self.digits.get(), 4)))
        sep = "" if self.sep.get() == "(none)" else self.sep.get()
        prefix = self.prefix.get()
        n = max(1, min(200, to_int(self.count.get(), 10)))
        lowercase = bool(self.lowercase.get())
        noambig = bool(self.noambig.get())

        names = []
        seen = set()
        # retry a few times so batch output stays unique within the run
        attempts = 0
        while len(names) < n and attempts < n * 20:
            attempts += 1
            name = generate_secure_username(
                style, length=length, digits=digits, separator=sep,
                lowercase=lowercase, no_ambiguous=noambig, prefix=prefix)
            if name not in seen:
                seen.add(name)
                names.append(name)

        self.out.set("\n".join(names))

        # rough entropy estimate for the status line
        if style.startswith("Word pair") or style.startswith("CamelCase"):
            pool = len(_USERNAME_ADJECTIVES) * len(set(_USERNAME_NOUNS))
            digit_pool = 8 if noambig else 10
            entropy = math.log2(pool) + (digits * math.log2(digit_pool) if digits else 0)
            note = f"~{entropy:.0f} bits  •  {len(names)} unique  •  word pools × {digits} digits"
        elif style.startswith("Random alphanumeric"):
            alpha = 32 if noambig else 36  # approx after look-alike filter
            entropy = length * math.log2(alpha)
            note = f"~{entropy:.0f} bits  •  {len(names)} unique  •  length {length}"
        elif style.startswith("Pronounceable"):
            entropy = (length // 2) * math.log2(len(_PRONOUNCE_CONS) * len(_PRONOUNCE_VOWELS))
            if digits:
                entropy += digits * math.log2(8 if noambig else 10)
            note = f"~{entropy:.0f} bits  •  {len(names)} unique  •  CV pattern"
        else:
            nbytes = max(2, min(32, (length + 1) // 2))
            entropy = nbytes * 8
            note = f"~{entropy:.0f} bits  •  {len(names)} unique  •  {nbytes} random bytes"
        self.info.configure(text=note)


class TokenPanel(ctk.CTkScrollableFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self.grid_columnconfigure(0, weight=1)
        section_title(self, "Secrets & Tokens").grid(row=0, column=0, sticky="w", pady=(0, 14))

        row = ctk.CTkFrame(self, fg_color="transparent")
        row.grid(row=1, column=0, sticky="w", pady=(0, 12))
        ctk.CTkLabel(row, text="Bytes of randomness:").grid(row=0, column=0, padx=(0, 8))
        self.nbytes = ctk.CTkEntry(row, width=80); self.nbytes.insert(0, "32")
        self.nbytes.grid(row=0, column=1)
        ctk.CTkLabel(row, text="Format:").grid(row=0, column=2, padx=(16, 8))
        self.fmt = ctk.CTkOptionMenu(row, values=["hex", "base64", "base64url", "url-safe token"])
        self.fmt.grid(row=0, column=3)
        ctk.CTkButton(row, text="Generate", fg_color=ACCENT, hover_color=ACCENT_HOVER, text_color=ACCENT_TEXT,
                      command=self.generate).grid(row=0, column=4, padx=12)

        cnt = ctk.CTkFrame(self, fg_color="transparent")
        cnt.grid(row=2, column=0, sticky="w", pady=(0, 12))
        ctk.CTkLabel(cnt, text="How many:").grid(row=0, column=0, padx=(0, 8))
        self.count = ctk.CTkEntry(cnt, width=70); self.count.insert(0, "1")
        self.count.grid(row=0, column=1)
        grey_button(cnt, "Generate UUID4", self.gen_uuid).grid(row=0, column=2, padx=12)

        self.out = OutputBox(self, height=220, save_cb=lambda: save_text_dialog(
            self.out.get(), "secrets.txt", [("Text", "*.txt"), ("All", "*.*")]))
        self.out.grid(row=3, column=0, sticky="nsew")
        self.grid_rowconfigure(3, weight=1)

    def generate(self):
        n = max(1, min(4096, to_int(self.nbytes.get(), 32)))
        how_many = max(1, min(100, to_int(self.count.get(), 1)))
        f = self.fmt.get()

        def one():
            raw = secrets.token_bytes(n)
            if f == "hex":
                return raw.hex()
            if f == "base64":
                return base64.b64encode(raw).decode()
            if f == "base64url":
                return base64.urlsafe_b64encode(raw).decode()
            return secrets.token_urlsafe(n)

        self.out.set("\n".join(one() for _ in range(how_many)))

    def gen_uuid(self):
        how_many = max(1, min(100, to_int(self.count.get(), 1)))
        self.out.set("\n".join(str(uuid.uuid4()) for _ in range(how_many)))


class HashPanel(ctk.CTkScrollableFrame):
    ALGOS = ["sha256", "sha512", "sha384", "sha3_256", "sha3_512",
             "blake2b", "blake2s", "sha1", "md5"]

    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self.grid_columnconfigure(0, weight=1)
        section_title(self, "Hashing").grid(row=0, column=0, sticky="w", pady=(0, 14))

        top = ctk.CTkFrame(self, fg_color="transparent")
        top.grid(row=1, column=0, sticky="w", pady=(0, 8))
        ctk.CTkLabel(top, text="Algorithm:").grid(row=0, column=0, padx=(0, 8))
        self.algo = ctk.CTkOptionMenu(top, values=self.ALGOS)
        self.algo.grid(row=0, column=1)

        ctk.CTkLabel(self, text="Text input:").grid(row=2, column=0, sticky="w")
        self.text_in = ctk.CTkTextbox(self, height=120, font=MONO)
        self.text_in.grid(row=3, column=0, sticky="ew", pady=(0, 8))

        buttons = ctk.CTkFrame(self, fg_color="transparent")
        buttons.grid(row=4, column=0, sticky="w", pady=(0, 12))
        ctk.CTkButton(buttons, text="Hash text", fg_color=ACCENT, hover_color=ACCENT_HOVER, text_color=ACCENT_TEXT,
                      command=self.hash_text).grid(row=0, column=0)
        self.file_btn = grey_button(buttons, "Hash a file…", self.hash_file)
        self.file_btn.grid(row=0, column=1, padx=12)

        self.out = OutputBox(self, height=160)
        self.out.grid(row=5, column=0, sticky="nsew")
        self.grid_rowconfigure(5, weight=1)

        verify_row = ctk.CTkFrame(self, fg_color="transparent")
        verify_row.grid(row=6, column=0, sticky="ew", pady=(10, 0))
        verify_row.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(verify_row, text="Verify against:").grid(row=0, column=0, padx=(0, 8))
        self.expected = ctk.CTkEntry(verify_row, placeholder_text="paste an expected checksum")
        self.expected.grid(row=0, column=1, sticky="ew")
        ctk.CTkButton(verify_row, text="Check", width=90, fg_color=ACCENT, hover_color=ACCENT_HOVER, text_color=ACCENT_TEXT,
                      command=self.verify).grid(row=0, column=2, padx=(8, 0))
        self.verify_status = ctk.CTkLabel(self, text="", anchor="w", font=("", 14, "bold"))
        self.verify_status.grid(row=7, column=0, sticky="w", pady=(6, 0))

    def hash_text(self):
        data = self.text_in.get("1.0", "end").rstrip("\n").encode("utf-8")
        h = hashlib.new(self.algo.get()); h.update(data)
        self.out.set(f"{self.algo.get()}:\n{h.hexdigest()}")

    def hash_file(self):
        path = filedialog.askopenfilename(title="Choose a file to hash")
        if not path:
            return
        algo = self.algo.get()

        def work():
            h = hashlib.new(algo)
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            name = path.replace("\\", "/").split("/")[-1]
            return f"{algo}  ({name}):\n{h.hexdigest()}"

        # keep UI responsive for large files
        run_task(self.app, self.file_btn, "Hash a file…", work,
                 lambda res: self.out.set(res), error_title="Read error",
                 busy_text="Hashing…")

    def verify(self):
        expected = self.expected.get().strip().lower().replace(":", "").replace(" ", "")
        if not expected:
            self.verify_status.configure(text="Enter a checksum to compare.", text_color=MUTED)
            return
        current = self.out.get()
        if not current:
            self.verify_status.configure(text="Hash something first.", text_color=MUTED)
            return
        actual = current.strip().splitlines()[-1].strip().lower()
        # constant-time comparison so a mismatch can't be timed character by character
        if secrets.compare_digest(actual, expected):
            self.verify_status.configure(text="✓ Match", text_color=OK)
        else:
            self.verify_status.configure(text="✗ No match", text_color=DANGER)


class JWTPanel(ctk.CTkScrollableFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self.grid_columnconfigure(0, weight=1)
        section_title(self, "JSON Web Tokens").grid(row=0, column=0, sticky="w", pady=(0, 14))

        top = ctk.CTkFrame(self, fg_color="transparent")
        top.grid(row=1, column=0, sticky="w", pady=(0, 10))
        self.mode = ctk.CTkSegmentedButton(top, values=["Encode", "Decode"])
        self.mode.set("Encode"); self.mode.grid(row=0, column=0)
        ctk.CTkLabel(top, text="Algorithm:").grid(row=0, column=1, padx=(16, 8))
        self.alg = ctk.CTkOptionMenu(top, values=["HS256", "HS384", "HS512", "RS256"])
        self.alg.grid(row=0, column=2)

        ctk.CTkLabel(self, text="Payload JSON (encode)  /  Token (decode):").grid(row=2, column=0, sticky="w")
        self.payload = ctk.CTkTextbox(self, height=140, font=MONO)
        self.payload.insert("1.0", '{\n  "sub": "1234567890",\n  "name": "Jane Doe",\n  "role": "admin"\n}')
        self.payload.grid(row=3, column=0, sticky="ew", pady=(0, 8))

        ctk.CTkLabel(self, text="Secret (HS*)  or  PEM key (RS256):").grid(row=4, column=0, sticky="w")
        self.key = ctk.CTkTextbox(self, height=80, font=MONO)
        self.key.insert("1.0", "my-super-secret-key")
        self.key.grid(row=5, column=0, sticky="ew", pady=(0, 8))

        opts = ctk.CTkFrame(self, fg_color="transparent")
        opts.grid(row=6, column=0, sticky="w", pady=(0, 10))
        self.add_exp = ctk.CTkCheckBox(opts, text="Add exp (+1h) & iat on encode"); self.add_exp.select()
        self.add_exp.grid(row=0, column=0, padx=(0, 16))
        self.verify = ctk.CTkCheckBox(opts, text="Verify signature on decode"); self.verify.select()
        self.verify.grid(row=0, column=1)

        ctk.CTkButton(self, text="Run", fg_color=ACCENT, hover_color=ACCENT_HOVER, text_color=ACCENT_TEXT, command=self.run).grid(row=7, column=0, sticky="w")
        self.out = OutputBox(self, height=160)
        self.out.grid(row=8, column=0, sticky="nsew", pady=(10, 0))
        self.grid_rowconfigure(8, weight=1)

    def run(self):
        alg = self.alg.get()
        key = self.key.get("1.0", "end").strip()
        body = self.payload.get("1.0", "end").strip()
        try:
            if self.mode.get() == "Encode":
                data = json.loads(body)
                if self.add_exp.get():
                    now = datetime.datetime.now(datetime.timezone.utc)
                    data.setdefault("iat", int(now.timestamp()))
                    data["exp"] = int((now + datetime.timedelta(hours=1)).timestamp())
                self.out.set(pyjwt.encode(data, key, algorithm=alg))
            else:
                if self.verify.get():
                    decoded = pyjwt.decode(body, key, algorithms=[alg])
                else:
                    decoded = pyjwt.decode(body, options={"verify_signature": False})
                header = pyjwt.get_unverified_header(body)
                self.out.set("HEADER:\n" + json.dumps(header, indent=2) +
                             "\n\nPAYLOAD:\n" + json.dumps(decoded, indent=2))
        except (pyjwt.PyJWTError, json.JSONDecodeError, ValueError) as err:
            self.out.set(f"Error: {err}")


class KeyPairPanel(ctk.CTkScrollableFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self.grid_columnconfigure(0, weight=1)
        section_title(self, "Asymmetric Key Pairs (PEM)").grid(row=0, column=0, sticky="w", pady=(0, 14))

        top = ctk.CTkFrame(self, fg_color="transparent")
        top.grid(row=1, column=0, sticky="w", pady=(0, 10))
        ctk.CTkLabel(top, text="Type:").grid(row=0, column=0, padx=(0, 8))
        self.kind = ctk.CTkOptionMenu(
            top, values=["RSA 2048", "RSA 3072", "RSA 4096",
                         "EC P-256", "EC P-384", "EC P-521", "Ed25519"])
        self.kind.grid(row=0, column=1)
        self.btn = ctk.CTkButton(top, text="Generate", fg_color=ACCENT, hover_color=ACCENT_HOVER, text_color=ACCENT_TEXT, command=self.generate)
        self.btn.grid(row=0, column=2, padx=12)

        pf, self.passphrase = passphrase_row(self, "Encrypt private key with:")
        pf.grid(row=2, column=0, sticky="w", pady=(0, 12))

        ctk.CTkLabel(self, text="Private key:").grid(row=3, column=0, sticky="w")
        self.priv = OutputBox(self, height=200, save_cb=lambda: save_text_dialog(
            self.priv.get(), "private_key.pem", PEM_FILES))
        self.priv.grid(row=4, column=0, sticky="ew", pady=(0, 8))

        ctk.CTkLabel(self, text="Public key:").grid(row=5, column=0, sticky="w")
        self.pub = OutputBox(self, height=140, save_cb=lambda: save_text_dialog(
            self.pub.get(), "public_key.pem", PEM_FILES))
        self.pub.grid(row=6, column=0, sticky="ew")

    def generate(self):
        kind = self.kind.get()
        passphrase = self.passphrase.get()

        def work():
            k = make_key(kind)
            priv = key_to_pem(k, passphrase)
            pub = k.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo).decode()
            return priv, pub

        def show(res):
            self.priv.set(res[0]); self.pub.set(res[1])

        run_task(self.app, self.btn, "Generate", work, show)


class SSHPanel(ctk.CTkScrollableFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self.grid_columnconfigure(0, weight=1)
        section_title(self, "OpenSSH Keys").grid(row=0, column=0, sticky="w", pady=(0, 14))

        top = ctk.CTkFrame(self, fg_color="transparent")
        top.grid(row=1, column=0, sticky="w", pady=(0, 8))
        ctk.CTkLabel(top, text="Type:").grid(row=0, column=0, padx=(0, 8))
        self.kind = ctk.CTkOptionMenu(top, values=["Ed25519", "RSA 4096", "RSA 2048"])
        self.kind.grid(row=0, column=1)
        ctk.CTkLabel(top, text="Comment:").grid(row=0, column=2, padx=(16, 8))
        self.comment = ctk.CTkEntry(top, width=200)
        self.comment.insert(0, "user@host")
        self.comment.grid(row=0, column=3)
        self.btn = ctk.CTkButton(top, text="Generate", fg_color=ACCENT, hover_color=ACCENT_HOVER, text_color=ACCENT_TEXT, command=self.generate)
        self.btn.grid(row=0, column=4, padx=12)

        pf, self.passphrase = passphrase_row(self, "Encrypt private key with:")
        pf.grid(row=2, column=0, sticky="w", pady=(0, 12))

        ctk.CTkLabel(self, text="Private key (id_ed25519 / id_rsa):").grid(row=3, column=0, sticky="w")
        self.priv = OutputBox(self, height=200, save_cb=lambda: save_text_dialog(
            self.priv.get(), "id_key", [("All", "*.*")]))
        self.priv.grid(row=4, column=0, sticky="ew", pady=(0, 8))

        ctk.CTkLabel(self, text="Public key (.pub):").grid(row=5, column=0, sticky="w")
        self.pub = OutputBox(self, height=120, save_cb=lambda: save_text_dialog(
            self.pub.get(), "id_key.pub", [("PUB", "*.pub"), ("All", "*.*")]))
        self.pub.grid(row=6, column=0, sticky="ew")

    def generate(self):
        kind = self.kind.get()
        comment = self.comment.get().strip()
        passphrase = self.passphrase.get()

        def work():
            k = make_key(kind)
            priv = key_to_pem(k, passphrase, serialization.PrivateFormat.OpenSSH)
            pub = k.public_key().public_bytes(
                serialization.Encoding.OpenSSH,
                serialization.PublicFormat.OpenSSH).decode()
            if comment:
                pub = f"{pub} {comment}"
            return priv, pub

        def show(res):
            self.priv.set(res[0]); self.pub.set(res[1])

        run_task(self.app, self.btn, "Generate", work, show)


class CSRPanel(ctk.CTkScrollableFrame):
    """Requester side: generate a private key + CSR to send to a CA."""
    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self.grid_columnconfigure(0, weight=1)
        section_title(self, "Make a Signing Request").grid(row=0, column=0, sticky="w", pady=(0, 14))

        form = FormGrid(self)
        form.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        self.cn = form.field(0, 0, "Common Name:", "example.com")
        self.org = form.field(0, 2, "Organization:", "Example Inc")
        self.country = form.field(1, 0, "Country (2):", "US", width=W_SHORT)
        self.ou = form.field(1, 2, "Org Unit:", "")
        self.sans = form.field(2, 0, "SANs (comma sep):", "example.com, www.example.com",
                               width=W_WIDE, span=3)
        self.kind = form.option(3, 0, "Key type:",
                                ["RSA 2048", "RSA 4096", "EC P-256", "EC P-384", "Ed25519"])

        pf, self.passphrase = passphrase_row(self, "Encrypt private key with:")
        pf.grid(row=2, column=0, sticky="w", pady=(0, 10))

        self.btn = ctk.CTkButton(self, text="Generate key + CSR", fg_color=ACCENT, hover_color=ACCENT_HOVER, text_color=ACCENT_TEXT, command=self.generate)
        self.btn.grid(row=3, column=0, sticky="w", pady=(0, 10))

        ctk.CTkLabel(self, text="CSR — send this to the CA:").grid(row=4, column=0, sticky="w")
        self.csr_out = OutputBox(self, height=170, save_cb=lambda: save_text_dialog(
            self.csr_out.get(), "request.csr", [("CSR", "*.csr *.pem"), ("All", "*.*")]))
        self.csr_out.grid(row=5, column=0, sticky="ew", pady=(0, 8))

        ctk.CTkLabel(self, text="Private key — keep this secret, never send it:").grid(row=6, column=0, sticky="w")
        self.key_out = OutputBox(self, height=170, save_cb=lambda: save_text_dialog(
            self.key_out.get(), "request.key", KEY_FILES))
        self.key_out.grid(row=7, column=0, sticky="ew")

    def generate(self):
        cn = self.cn.get()
        org = self.org.get()
        ou = self.ou.get()
        country = self.country.get()[:2].upper()
        san_str = self.sans.get()
        kind = self.kind.get()
        passphrase = self.passphrase.get()

        def work():
            key = make_key(kind)
            attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
            if org:
                attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
            if ou:
                attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
            if country:
                attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
            builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(attrs))
            items = split_csv(san_str)
            if cn and cn not in items:
                items.insert(0, cn)
            sans = san_objects(items)
            if sans:
                builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
            csr = builder.sign(key, sign_hash_for(key))
            csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
            return csr_pem, key_to_pem(key, passphrase)

        def show(res):
            self.csr_out.set(res[0]); self.key_out.set(res[1])

        run_task(self.app, self.btn, "Generate key + CSR", work, show)


class CertPanel(ctk.CTkScrollableFrame):
    """Generate a self-signed root CA. Stores the CA in memory for the Sign panel."""
    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self.grid_columnconfigure(0, weight=1)
        self.last_cert_pem = None
        self.last_key_pem = None  # unencrypted, in-memory only
        # Mirrored onto the App so lazy panel teardown does not lose the last CA.

        section_title(self, "Root Certificate Authority").grid(row=0, column=0, sticky="w", pady=(0, 14))

        form = FormGrid(self)
        form.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        self.cn = form.field(0, 0, "Common Name:", "My Root CA")
        self.org = form.field(0, 2, "Organization:", "Example Inc")
        self.country = form.field(1, 0, "Country (2):", "US", width=W_SHORT)
        self.days = form.field(1, 2, "Valid days:", "3650", width=100)
        self.kind = form.option(2, 0, "Key type:", ["RSA 4096", "RSA 2048", "EC P-256", "Ed25519"])

        pf, self.passphrase = passphrase_row(self, "Encrypt CA private key with:")
        pf.grid(row=2, column=0, sticky="w", pady=(0, 10))

        self.btn = ctk.CTkButton(self, text="Generate root cert", fg_color=ACCENT, hover_color=ACCENT_HOVER, text_color=ACCENT_TEXT, command=self.generate)
        self.btn.grid(row=3, column=0, sticky="w", pady=(0, 10))

        ctk.CTkLabel(self, text="Certificate (PEM):").grid(row=4, column=0, sticky="w")
        self.cert = OutputBox(self, height=170, save_cb=lambda: save_text_dialog(
            self.cert.get(), "rootCA.crt", CERT_FILES))
        self.cert.grid(row=5, column=0, sticky="ew", pady=(0, 8))

        ctk.CTkLabel(self, text="Private key (PEM):").grid(row=6, column=0, sticky="w")
        self.key = OutputBox(self, height=150, save_cb=lambda: save_text_dialog(
            self.key.get(), "rootCA.key", KEY_FILES))
        self.key.grid(row=7, column=0, sticky="ew")

    def generate(self):
        cn = self.cn.get()
        org = self.org.get()
        country = self.country.get()[:2].upper()
        days = to_int(self.days.get(), 3650)
        kind = self.kind.get()
        passphrase = self.passphrase.get()

        def work():
            key = make_key(kind)
            name = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, cn),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            ])
            now = datetime.datetime.now(datetime.timezone.utc)
            cert = (
                x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=1))
                .not_valid_after(now + datetime.timedelta(days=days))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    key_encipherment=False, content_commitment=False,
                    data_encipherment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False), critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                .sign(key, sign_hash_for(key))
            )
            cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
            plain_key_pem = key_to_pem(key, None)          # unencrypted, kept in memory
            shown_key_pem = key_to_pem(key, passphrase)    # what the user sees / saves
            return cert_pem, plain_key_pem, shown_key_pem

        def show(res):
            cert_pem, plain_key_pem, shown_key_pem = res
            self.cert.set(cert_pem)
            self.key.set(shown_key_pem)
            self.last_cert_pem = cert_pem
            self.last_key_pem = plain_key_pem
            self.app.last_ca_cert_pem = cert_pem
            self.app.last_ca_key_pem = plain_key_pem

        run_task(self.app, self.btn, "Generate root cert", work, show)


class SignPanel(ctk.CTkScrollableFrame):
    """Issue a server/leaf certificate — either by generating a key or signing an external CSR."""
    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self.grid_columnconfigure(0, weight=1)
        section_title(self, "Sign a Certificate").grid(row=0, column=0, sticky="w", pady=(0, 14))

        # --- CA material ---
        ca_head = ctk.CTkFrame(self, fg_color="transparent")
        ca_head.grid(row=1, column=0, sticky="w", pady=(0, 4))
        ctk.CTkLabel(ca_head, text="Certificate Authority",
                     font=("", 15, "bold")).grid(row=0, column=0, padx=(0, 12))
        grey_button(ca_head, "Use last generated root CA", self.use_last_ca, height=28).grid(row=0, column=1)

        ctk.CTkLabel(self, text="CA certificate (PEM):").grid(row=2, column=0, sticky="w")
        self.ca_cert = OutputBox(self, height=110)
        self.ca_cert.grid(row=3, column=0, sticky="ew", pady=(0, 4))
        grey_button(self, "Load CA cert…", lambda: load_text_into(self.ca_cert), height=28).grid(
            row=4, column=0, sticky="w", pady=(0, 8))

        ctk.CTkLabel(self, text="CA private key (PEM):").grid(row=5, column=0, sticky="w")
        self.ca_key = OutputBox(self, height=110)
        self.ca_key.grid(row=6, column=0, sticky="ew", pady=(0, 4))
        krow = ctk.CTkFrame(self, fg_color="transparent")
        krow.grid(row=7, column=0, sticky="w", pady=(0, 12))
        grey_button(krow, "Load CA key…", lambda: load_text_into(self.ca_key), height=28).grid(
            row=0, column=0, padx=(0, 12))
        pf, self.ca_pass = passphrase_row(krow, "CA key passphrase:")
        pf.grid(row=0, column=1)

        # --- mode ---
        mode_row = ctk.CTkFrame(self, fg_color="transparent")
        mode_row.grid(row=8, column=0, sticky="w", pady=(4, 8))
        ctk.CTkLabel(mode_row, text="Mode:", font=("", 15, "bold")).grid(row=0, column=0, padx=(0, 12))
        self.mode = ctk.CTkSegmentedButton(
            mode_row, values=["Generate key + sign", "Sign external CSR"], command=self._mode_changed)
        self.mode.set("Generate key + sign")
        self.mode.grid(row=0, column=1)

        # --- CSR input (hidden unless CSR mode) ---
        self.csr_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.csr_frame.grid(row=9, column=0, sticky="ew", pady=(0, 8))
        self.csr_frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(self.csr_frame, text="Certificate Signing Request (PEM):").grid(row=0, column=0, sticky="w")
        self.csr_in = OutputBox(self.csr_frame, height=120)
        self.csr_in.grid(row=1, column=0, sticky="ew", pady=(0, 4))
        grey_button(self.csr_frame, "Load CSR…",
                    lambda: load_text_into(self.csr_in, "Choose a CSR file"), height=28).grid(
            row=2, column=0, sticky="w")
        ctk.CTkLabel(self.csr_frame,
                     text="Subject and public key are taken from the CSR. The requester keeps their private key.",
                     text_color=MUTED).grid(row=3, column=0, sticky="w", pady=(4, 0))

        # --- generate-mode leaf details ---
        self.gen_frame = FormGrid(self)
        self.gen_frame.grid(row=10, column=0, sticky="ew", pady=(0, 8))
        self.cn = self.gen_frame.field(0, 0, "Common Name:", "example.com")
        self.org = self.gen_frame.field(0, 2, "Organization:", "Example Inc")
        self.country = self.gen_frame.field(1, 0, "Country (2):", "US", width=W_SHORT)
        self.kind = self.gen_frame.option(2, 0, "Key type:",
                                          ["RSA 2048", "RSA 4096", "EC P-256", "Ed25519"])

        # --- shared decisions (apply to both modes) ---
        shared = FormGrid(self)
        shared.grid(row=11, column=0, sticky="ew", pady=(0, 4))
        self.days = shared.field(0, 0, "Valid days:", "397", width=100)
        self.sans = shared.field(1, 0, "SANs (comma sep):",
                                 "example.com, www.example.com, 127.0.0.1", width=W_WIDE, span=3)
        self.sans_note = ctk.CTkLabel(self, text="", text_color=MUTED)
        self.sans_note.grid(row=12, column=0, sticky="w", pady=(0, 8))

        eku_row = ctk.CTkFrame(self, fg_color="transparent")
        eku_row.grid(row=13, column=0, sticky="w", pady=(0, 8))
        self.server_auth = ctk.CTkCheckBox(eku_row, text="Server auth"); self.server_auth.select()
        self.server_auth.grid(row=0, column=0, padx=(0, 16))
        self.client_auth = ctk.CTkCheckBox(eku_row, text="Client auth")
        self.client_auth.grid(row=0, column=1)

        pf2, self.leaf_pass = passphrase_row(self, "Encrypt server key with:")
        pf2.grid(row=14, column=0, sticky="w", pady=(0, 8))
        self.leaf_pass_frame = pf2

        self.btn = ctk.CTkButton(self, text="Sign certificate", fg_color=ACCENT, hover_color=ACCENT_HOVER, text_color=ACCENT_TEXT, command=self.sign)
        self.btn.grid(row=15, column=0, sticky="w", pady=(0, 10))

        ctk.CTkLabel(self, text="Signed certificate (PEM):").grid(row=16, column=0, sticky="w")
        self.out_cert = OutputBox(self, height=150, save_cb=lambda: save_text_dialog(
            self.out_cert.get(), "server.crt", CERT_FILES))
        self.out_cert.grid(row=17, column=0, sticky="ew", pady=(0, 8))

        self.key_label = ctk.CTkLabel(self, text="Server private key (PEM):")
        self.key_label.grid(row=18, column=0, sticky="w")
        self.out_key = OutputBox(self, height=150, save_cb=lambda: save_text_dialog(
            self.out_key.get(), "server.key", KEY_FILES))
        self.out_key.grid(row=19, column=0, sticky="ew", pady=(0, 8))

        ctk.CTkLabel(self, text="Full chain (leaf + CA):").grid(row=20, column=0, sticky="w")
        self.out_chain = OutputBox(self, height=150, save_cb=lambda: save_text_dialog(
            self.out_chain.get(), "fullchain.pem", PEM_FILES))
        self.out_chain.grid(row=21, column=0, sticky="ew")

        self._mode_changed("Generate key + sign")

    def _mode_changed(self, mode):
        csr = (mode == "Sign external CSR")
        for w in (self.gen_frame, self.leaf_pass_frame, self.key_label, self.out_key):
            (w.grid_remove if csr else w.grid)()
        (self.csr_frame.grid if csr else self.csr_frame.grid_remove)()
        self.sans_note.configure(
            text="Leave blank to use SANs from the CSR; fill in to override them." if csr
            else "The Common Name is added automatically as a SAN.")

    def use_last_ca(self):
        cert = getattr(self.app, "last_ca_cert_pem", None)
        key = getattr(self.app, "last_ca_key_pem", None)
        if not cert:
            messagebox.showinfo("No CA yet", "Generate a root cert in the Root CA tab first.")
            return
        self.ca_cert.set(cert)
        self.ca_key.set(key or "")
        self.ca_pass.delete(0, "end")

    @staticmethod
    def _build_common(builder, ca_cert, ca_key, days, sans, ekus):
        now = datetime.datetime.now(datetime.timezone.utc)
        builder = (
            builder
            .issuer_name(ca_cert.subject)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, key_encipherment=True, content_commitment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False)
        )
        if sans:
            builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
        if ekus:
            builder = builder.add_extension(x509.ExtendedKeyUsage(ekus), critical=False)
        return builder

    def sign(self):
        ca_cert_pem = self.ca_cert.get()
        ca_key_pem = self.ca_key.get()
        if not ca_cert_pem or not ca_key_pem:
            messagebox.showwarning("Missing CA", "Provide a CA certificate and private key.")
            return
        mode = self.mode.get()
        if mode == "Sign external CSR" and not self.csr_in.get():
            messagebox.showwarning("Missing CSR", "Paste or load a CSR to sign.")
            return

        ca_pass = self.ca_pass.get()
        csr_pem = self.csr_in.get()
        cn = self.cn.get()
        org = self.org.get()
        country = self.country.get()[:2].upper()
        san_str = self.sans.get()
        kind = self.kind.get()
        leaf_pass = self.leaf_pass.get()
        server_auth = bool(self.server_auth.get())
        client_auth = bool(self.client_auth.get())
        days = to_int(self.days.get(), 397)

        def work():
            ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode())
            ca_key = load_private_key(ca_key_pem, ca_pass)
            ekus = []
            if server_auth:
                ekus.append(ExtendedKeyUsageOID.SERVER_AUTH)
            if client_auth:
                ekus.append(ExtendedKeyUsageOID.CLIENT_AUTH)
            typed = split_csv(san_str)

            if mode == "Sign external CSR":
                csr = x509.load_pem_x509_csr(csr_pem.strip().encode())
                if not csr.is_signature_valid:
                    raise ValueError("CSR signature is invalid — the request is corrupt or tampered with.")
                if typed:
                    sans = san_objects(typed)
                else:
                    try:
                        sans = list(csr.extensions.get_extension_for_class(
                            x509.SubjectAlternativeName).value)
                    except x509.ExtensionNotFound:
                        sans = []
                if not sans:
                    raise ValueError(
                        "The CSR carries no SANs and none were entered above. Modern clients "
                        "reject certificates without a Subject Alternative Name — add SANs in "
                        "the field before signing.")
                builder = (x509.CertificateBuilder()
                           .subject_name(csr.subject)
                           .public_key(csr.public_key())
                           .add_extension(
                               x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
                               critical=False))
                builder = self._build_common(builder, ca_cert, ca_key, days, sans, ekus)
                leaf = builder.sign(ca_key, sign_hash_for(ca_key))
                cert_pem = leaf.public_bytes(serialization.Encoding.PEM).decode()
                key_pem = None
            else:
                leaf_key = make_key(kind)
                subject = x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, cn),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                    x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                ])
                if cn and cn not in typed:
                    typed.insert(0, cn)
                sans = san_objects(typed)
                builder = (x509.CertificateBuilder()
                           .subject_name(subject)
                           .public_key(leaf_key.public_key())
                           .add_extension(
                               x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
                               critical=False))
                builder = self._build_common(builder, ca_cert, ca_key, days, sans, ekus)
                leaf = builder.sign(ca_key, sign_hash_for(ca_key))
                cert_pem = leaf.public_bytes(serialization.Encoding.PEM).decode()
                key_pem = key_to_pem(leaf_key, leaf_pass)
            chain = cert_pem + ca_cert_pem.strip() + "\n"
            return cert_pem, key_pem, chain

        def show(res):
            cert_pem, key_pem, chain = res
            self.out_cert.set(cert_pem)
            self.out_key.set(key_pem or "")
            self.out_chain.set(chain)

        run_task(self.app, self.btn, "Sign certificate", work, show, error_title="Signing failed")


class VerifyPanel(ctk.CTkScrollableFrame):
    """Confirm a leaf certificate was really issued by a given CA."""
    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self.grid_columnconfigure(0, weight=1)
        section_title(self, "Verify Chain").grid(row=0, column=0, sticky="w", pady=(0, 14))

        ctk.CTkLabel(self, text="Leaf / server certificate (PEM):").grid(row=1, column=0, sticky="w")
        self.leaf = OutputBox(self, height=130)
        self.leaf.grid(row=2, column=0, sticky="ew", pady=(0, 4))
        grey_button(self, "Load leaf…", lambda: load_text_into(self.leaf, "Choose leaf cert"),
                    height=28).grid(row=3, column=0, sticky="w", pady=(0, 10))

        cah = ctk.CTkFrame(self, fg_color="transparent")
        cah.grid(row=4, column=0, sticky="w")
        ctk.CTkLabel(cah, text="CA certificate (PEM):").grid(row=0, column=0, padx=(0, 12))
        grey_button(cah, "Use last generated root CA", self.use_last_ca, height=28).grid(row=0, column=1)
        self.ca = OutputBox(self, height=130)
        self.ca.grid(row=5, column=0, sticky="ew", pady=(0, 4))
        grey_button(self, "Load CA…", lambda: load_text_into(self.ca, "Choose CA cert"),
                    height=28).grid(row=6, column=0, sticky="w", pady=(0, 10))

        ctk.CTkButton(self, text="Verify", fg_color=ACCENT, hover_color=ACCENT_HOVER, text_color=ACCENT_TEXT, command=self.verify).grid(
            row=7, column=0, sticky="w", pady=(0, 8))
        self.verdict = ctk.CTkLabel(self, text="", anchor="w", font=("", 16, "bold"))
        self.verdict.grid(row=8, column=0, sticky="w", pady=(0, 6))
        self.out = OutputBox(self, height=240)
        self.out.grid(row=9, column=0, sticky="nsew")
        self.grid_rowconfigure(9, weight=1)

    def use_last_ca(self):
        cert = getattr(self.app, "last_ca_cert_pem", None)
        if not cert:
            messagebox.showinfo("No CA yet", "Generate a root cert in the Root CA tab first.")
            return
        self.ca.set(cert)

    def verify(self):
        leaf_pem, ca_pem = self.leaf.get(), self.ca.get()
        if not leaf_pem or not ca_pem:
            messagebox.showwarning("Missing input", "Provide both a leaf and a CA certificate.")
            return
        try:
            leaf = x509.load_pem_x509_certificate(leaf_pem.encode())
            ca = x509.load_pem_x509_certificate(ca_pem.encode())
        except (ValueError, TypeError) as err:
            self.verdict.configure(text="Could not parse a certificate", text_color=DANGER)
            self.out.set(f"Error: {err}")
            return

        now = datetime.datetime.now(datetime.timezone.utc)
        checks = []  # (label, ok, advisory?)

        name_ok = leaf.issuer == ca.subject
        checks.append(("Leaf's issuer matches CA's subject", name_ok, False))

        try:
            verify_cert_signature(leaf, ca.public_key())
            sig_ok, sig_note = True, "Signature verifies against the CA's public key"
        except InvalidSignature:
            sig_ok, sig_note = False, "Signature does NOT verify against the CA's key"
        checks.append((sig_note, sig_ok, False))

        try:
            ca_is_ca = ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        except x509.ExtensionNotFound:
            ca_is_ca = False
        checks.append(("CA cert is marked as a CA (BasicConstraints)", ca_is_ca, True))

        l_nb, l_na = cert_validity_window(leaf)
        leaf_valid = l_nb <= now <= l_na
        checks.append((f"Leaf is within its validity window (until {l_na:%Y-%m-%d})", leaf_valid, True))

        c_nb, c_na = cert_validity_window(ca)
        ca_valid = c_nb <= now <= c_na
        checks.append((f"CA is within its validity window (until {c_na:%Y-%m-%d})", ca_valid, True))

        issued = name_ok and sig_ok
        if issued and leaf_valid and ca_valid and ca_is_ca:
            self.verdict.configure(text="✓ Leaf is validly issued by this CA", text_color=OK)
        elif issued:
            self.verdict.configure(text="⚠ Issued by this CA, but with warnings below", text_color=WARN)
        else:
            self.verdict.configure(text="✗ Leaf is NOT issued by this CA", text_color=DANGER)

        lines = [f"  {'✓' if ok else ('⚠' if adv else '✗')}  {label}" for label, ok, adv in checks]
        lines += ["",
                  f"Leaf subject: {name_values(leaf.subject)}",
                  f"CA subject:   {name_values(ca.subject)}",
                  f"Checked at:   {now:%Y-%m-%d %H:%M:%S UTC}"]
        self.out.set("\n".join(lines))


class InspectorPanel(ctk.CTkScrollableFrame):
    """Decode any PEM certificate and show its fields, SANs, and expiry."""
    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self.grid_columnconfigure(0, weight=1)
        section_title(self, "Certificate Inspector").grid(row=0, column=0, sticky="w", pady=(0, 14))

        ctk.CTkLabel(self, text="Paste a certificate (PEM):").grid(row=1, column=0, sticky="w")
        self.cert_in = OutputBox(self, height=150)
        self.cert_in.grid(row=2, column=0, sticky="ew", pady=(0, 6))

        buttons = ctk.CTkFrame(self, fg_color="transparent")
        buttons.grid(row=3, column=0, sticky="w", pady=(0, 10))
        grey_button(buttons, "Load cert…",
                    lambda: load_text_into(self.cert_in, "Choose a certificate")).grid(
            row=0, column=0, padx=(0, 12))
        ctk.CTkButton(buttons, text="Inspect", fg_color=ACCENT, hover_color=ACCENT_HOVER, text_color=ACCENT_TEXT, command=self.inspect).grid(row=0, column=1)

        self.status = ctk.CTkLabel(self, text="", anchor="w", font=("", 14, "bold"))
        self.status.grid(row=4, column=0, sticky="w", pady=(0, 6))

        self.out = OutputBox(self, height=340)
        self.out.grid(row=5, column=0, sticky="nsew")
        self.grid_rowconfigure(5, weight=1)

    @staticmethod
    def _name_str(name):
        return ", ".join(f"{a.rfc4514_attribute_name}={a.value}" for a in name)

    def inspect(self):
        pem = self.cert_in.get()
        if not pem:
            messagebox.showwarning("Nothing to inspect", "Paste or load a certificate first.")
            return
        try:
            cert = x509.load_pem_x509_certificate(pem.encode())
        except (ValueError, TypeError) as err:
            self.status.configure(text="Not a valid certificate", text_color=DANGER)
            self.out.set(f"Error: {err}")
            return

        now = datetime.datetime.now(datetime.timezone.utc)
        nvb, nva = cert_validity_window(cert)
        days_left = (nva - now).days
        if now < nvb:
            self.status.configure(text="⚠ Not yet valid", text_color=WARN)
        elif now > nva:
            self.status.configure(text="✗ EXPIRED", text_color=DANGER)
        elif days_left <= 30:
            self.status.configure(text=f"⚠ Expiring soon — {days_left} days left", text_color=WARN)
        else:
            self.status.configure(text=f"✓ Valid — {days_left} days left", text_color=OK)

        lines = []

        def add(label, val):
            lines.append(f"{label:<22}{val}")

        sig = cert.signature_hash_algorithm
        add("Subject:", self._name_str(cert.subject))
        add("Issuer:", self._name_str(cert.issuer))
        add("Self-signed:", "yes" if cert.subject == cert.issuer else "no")
        add("Serial:", format(cert.serial_number, "x"))
        add("Version:", cert.version.name)
        add("Not before:", nvb.strftime("%Y-%m-%d %H:%M:%S UTC"))
        add("Not after:", nva.strftime("%Y-%m-%d %H:%M:%S UTC"))
        add("Days remaining:", str(days_left))
        add("Public key:", describe_public_key(cert.public_key()))
        add("Signature:", f"{cert.signature_algorithm_oid._name}" + (f" ({sig.name})" if sig else ""))
        add("SHA-256 FP:", cert.fingerprint(hashes.SHA256()).hex(":"))
        add("SHA-1 FP:", cert.fingerprint(hashes.SHA1()).hex(":"))

        lines += ["", "Extensions:"]

        def show_ext(cls, fmt):
            try:
                extension = cert.extensions.get_extension_for_class(cls)
            except x509.ExtensionNotFound:
                return
            crit = " (critical)" if extension.critical else ""
            lines.append(f"  {cls.__name__}{crit}: {fmt(extension.value)}")

        show_ext(x509.SubjectAlternativeName,
                 lambda v: ", ".join(str(g.value) for g in v) or "(none)")
        show_ext(x509.BasicConstraints,
                 lambda v: f"CA={v.ca}" + (f", path_len={v.path_length}"
                                           if v.path_length is not None else ""))
        show_ext(x509.KeyUsage, self._fmt_key_usage)
        show_ext(x509.ExtendedKeyUsage,
                 lambda v: ", ".join(str(getattr(oid, "_name", oid.dotted_string)) for oid in v) or "(none)")
        show_ext(x509.SubjectKeyIdentifier, lambda v: v.digest.hex())
        show_ext(x509.AuthorityKeyIdentifier,
                 lambda v: v.key_identifier.hex() if v.key_identifier else "(no key id)")

        self.out.set("\n".join(lines))

    @staticmethod
    def _fmt_key_usage(v):
        flags = []
        for attr in ("digital_signature", "content_commitment", "key_encipherment",
                     "data_encipherment", "key_agreement", "key_cert_sign", "crl_sign"):
            try:
                if getattr(v, attr):
                    flags.append(attr)
            except ValueError:
                pass
        return ", ".join(flags) or "(none)"


# ---------- opt-in analytics ----------
class Analytics:
    """Privacy-respecting, opt-in usage analytics.

    HARD GUARANTEE: this never transmits anything sensitive — no passwords, keys,
    secrets, certificates, file contents, or any value the user typed. It sends
    only an anonymous random install id, the app version, the OS name, whether the
    build is frozen, and coarse events (e.g. which tab was opened). Every send runs
    on a background thread and fails silently when offline or blocked.
    """
    def __init__(self):
        self.enabled = False
        self.install_id = uuid_hex()
        self.appearance = "Dark"
        self._decided = CONFIG_FILE.exists()
        self._load()

    def _load(self):
        try:
            data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            self.enabled = bool(data.get("analytics_enabled", False))
            self.install_id = data.get("install_id") or self.install_id
            appearance = str(data.get("appearance", "Dark")).title()
            if appearance not in ("Dark", "Light", "System"):
                appearance = "Dark"
            self.appearance = appearance
        except (OSError, ValueError):
            pass

    @property
    def decided(self):
        """True once the user has made an analytics choice."""
        return self._decided

    def _write(self):
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            CONFIG_FILE.write_text(json.dumps({
                "analytics_enabled": self.enabled,
                "install_id": self.install_id,
                "appearance": self.appearance,
            }, indent=2), encoding="utf-8")
        except OSError:
            pass

    def save(self, enabled):
        self.enabled = bool(enabled)
        self._decided = True
        self._write()

    def save_appearance(self, appearance):
        appearance = str(appearance).title()
        if appearance not in ("Dark", "Light", "System"):
            return
        self.appearance = appearance
        self._write()

    def track(self, event, **props):
        if not self.enabled or not ANALYTICS_ENDPOINT or not ANALYTICS_API_KEY:
            return
        payload = {
            "event": event,
            "install_id": self.install_id,
            "version": APP_VERSION,
            "os": platform.system(),
            "frozen": bool(getattr(sys, "frozen", False)),
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            **props,
        }
        threading.Thread(target=self._send, args=(payload,), daemon=True).start()

    @staticmethod
    def _send(payload):
        try:
            req = urllib.request.Request(
                ANALYTICS_ENDPOINT, data=json.dumps(payload).encode(),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {ANALYTICS_API_KEY}",
                    "X-API-Key": ANALYTICS_API_KEY,
                    "User-Agent": f"SecKit/{APP_VERSION}",
                })
            urllib.request.urlopen(req, timeout=5).close()
        except Exception:  # noqa: BLE001 - offline/blocked/server-down must never surface
            pass


def uuid_hex():
    return uuid.uuid4().hex


def ask_analytics_consent(analytics):
    msg = (
        "Help improve SecKit?\n\n"
        "SecKit can send anonymous usage analytics to the developer:\n"
        "  •  a random install ID (not linked to you)\n"
        "  •  app version and operating system\n"
        "  •  which tools you open\n\n"
        "It NEVER sends passwords, keys, secrets, certificates, file contents, "
        "or anything you type — all cryptographic work stays on your machine.\n\n"
        "You can change this any time in the About tab.\n\n"
        "Share anonymous analytics?"
    )
    analytics.save(bool(messagebox.askyesno("Analytics", msg)))


class AboutPanel(ctk.CTkScrollableFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self.grid_columnconfigure(0, weight=1)

        head = ctk.CTkFrame(self, fg_color="transparent")
        head.grid(row=0, column=0, sticky="w", pady=(0, 14))
        if LOGO_ABOUT_PATH.is_file():
            self._logo = ctk.CTkImage(
                light_image=_pil_open(LOGO_ABOUT_PATH),
                dark_image=_pil_open(LOGO_ABOUT_PATH),
                size=(72, 72))
            ctk.CTkLabel(head, image=self._logo, text="").grid(
                row=0, column=0, rowspan=2, padx=(0, 14))
        section_title(head, "About SecKit").grid(row=0, column=1, sticky="w")
        ctk.CTkLabel(head, text=f"by {DEV_NAME}", text_color=MUTED,
                     font=(UI_FONT, 13)).grid(row=1, column=1, sticky="w")

        info = (
            f"SecKit — Security Toolkit\n"
            f"Version {APP_VERSION}\n\n"
            f"Author:     {AUTHOR_NAME}\n"
            f"Developer:  {DEV_NAME}\n"
            f"Contact:    {DEV_EMAIL}\n"
            f"Web:        {DEV_SITE}\n\n"
            "An all-in-one desktop toolkit for passwords, usernames, tokens,\n"
            "hashing, JWTs, keys, and X.509 certificates. Every cryptographic\n"
            "operation runs locally on your machine — nothing sensitive ever\n"
            "leaves it."
        )
        ctk.CTkLabel(self, text=info, justify="left", anchor="w", font=MONO).grid(
            row=1, column=0, sticky="w", pady=(0, 18))

        ctk.CTkLabel(self, text="Privacy", font=(TITLE_FONT, 15, "bold"),
                     text_color=(BRAND_NAVY_DEEP, BRAND_YELLOW)).grid(
            row=2, column=0, sticky="w")
        self.analytics_var = ctk.BooleanVar(value=app.analytics.enabled)
        ctk.CTkSwitch(self, text="Share anonymous usage analytics",
                      variable=self.analytics_var, command=self._toggle).grid(
            row=3, column=0, sticky="w", pady=(6, 4))
        ctk.CTkLabel(
            self,
            text="Only an anonymous ID, app version, OS, and which tab you open.\n"
                 "Never passwords, keys, secrets, certificates, or anything you type.",
            justify="left", anchor="w", text_color=MUTED).grid(row=4, column=0, sticky="w")

    def _toggle(self):
        self.app.analytics.save(self.analytics_var.get())


# ---------- main app shell ----------
class App(ctk.CTk):
    PANELS = [
        ("Passwords", PasswordPanel), ("Usernames", UsernamePanel),
        ("Secrets", TokenPanel), ("Hashing", HashPanel),
        ("JWT", JWTPanel), ("Key Pairs", KeyPairPanel), ("SSH Keys", SSHPanel),
        ("Make CSR", CSRPanel), ("Root CA", CertPanel), ("Sign Cert", SignPanel),
        ("Verify", VerifyPanel), ("Inspector", InspectorPanel), ("About", AboutPanel),
    ]

    def __init__(self):
        analytics = Analytics()
        # Apply saved theme before widgets exist — avoids a full restyle on first paint.
        ctk.set_appearance_mode(analytics.appearance.lower())

        super().__init__()
        self.analytics = analytics
        self.title(f"SecKit — {DEV_NAME} Security Toolkit  v{APP_VERSION}")
        self.geometry("1040x800")
        self.minsize(860, 580)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self._apply_window_icon()

        self._panel_classes = {label: cls for label, cls in self.PANELS}
        self.panels = {}
        self.buttons = {}
        self._current = None
        self._theme_job = None
        self._theme_busy = False
        self.last_ca_cert_pem = None
        self.last_ca_key_pem = None

        side = ctk.CTkFrame(self, width=220, corner_radius=0,
                            fg_color=(BRAND_GREY, BRAND_BLACK))
        side.grid(row=0, column=0, sticky="nsw")
        side.grid_rowconfigure(2, weight=1)
        side.grid_columnconfigure(0, weight=1)

        brand = ctk.CTkFrame(side, fg_color="transparent")
        brand.grid(row=0, column=0, padx=16, pady=(20, 4), sticky="ew")
        brand.grid_columnconfigure(1, weight=1)
        if LOGO_SIDEBAR_PATH.is_file():
            self._side_logo = ctk.CTkImage(
                light_image=_pil_open(LOGO_SIDEBAR_PATH),
                dark_image=_pil_open(LOGO_SIDEBAR_PATH),
                size=(40, 40))
            ctk.CTkLabel(brand, image=self._side_logo, text="").grid(
                row=0, column=0, rowspan=2, padx=(0, 10))
        ctk.CTkLabel(brand, text="SecKit", font=(TITLE_FONT, 22, "bold"),
                     text_color=(BRAND_NAVY_DEEP, BRAND_YELLOW)).grid(
            row=0, column=1, sticky="w")
        ctk.CTkLabel(brand, text=DEV_NAME, font=(UI_FONT, 11),
                     text_color=MUTED).grid(row=1, column=1, sticky="w")

        ctk.CTkLabel(side, text="security toolkit", text_color=MUTED,
                     font=(UI_FONT, 12)).grid(
            row=1, column=0, padx=20, pady=(0, 12), sticky="w")

        nav = ctk.CTkScrollableFrame(side, fg_color="transparent", width=190)
        nav.grid(row=2, column=0, sticky="nsew", padx=4)
        nav.grid_columnconfigure(0, weight=1)

        self.container = ctk.CTkFrame(self, fg_color="transparent")
        self.container.grid(row=0, column=1, sticky="nsew", padx=24, pady=24)
        self.container.grid_columnconfigure(0, weight=1)
        self.container.grid_rowconfigure(0, weight=1)

        for i, (label, _cls) in enumerate(self.PANELS):
            b = ctk.CTkButton(
                nav, text=label, anchor="w", height=36,
                fg_color="transparent", text_color=IDLE_TEXT,
                hover_color=("#FFE9A8", BRAND_NAVY),
                command=lambda name=label: self.show(name))
            b.grid(row=i, column=0, padx=8, pady=2, sticky="ew")
            self.buttons[label] = b

        self.theme_menu = ctk.CTkOptionMenu(
            side, values=["Dark", "Light", "System"],
            command=self._on_theme_selected)
        self.theme_menu.set(self.analytics.appearance)
        self.theme_menu.grid(row=3, column=0, padx=16, pady=16, sticky="s")

        self.show("Passwords")
        if not self.analytics.decided:
            self.after(300, lambda: ask_analytics_consent(self.analytics))
        self.analytics.track("app_start")

    def _apply_window_icon(self):
        try:
            if ICON_PATH.is_file():
                self.iconbitmap(str(ICON_PATH))
            elif LOGO_PATH.is_file():
                from PIL import ImageTk
                photo = ImageTk.PhotoImage(_pil_open(LOGO_PATH).resize((64, 64)))
                self._icon_photo = photo  # keep reference
                self.iconphoto(True, photo)
        except Exception:
            pass

    def _ensure_panel(self, label):
        """Create a panel the first time it is opened (keeps startup + theme switches light)."""
        panel = self.panels.get(label)
        if panel is not None:
            return panel
        cls = self._panel_classes[label]
        panel = cls(self.container, self)
        panel.grid(row=0, column=0, sticky="nsew")
        panel.grid_remove()
        self.panels[label] = panel
        return panel

    def _drop_inactive_panels(self):
        """Destroy hidden panels so appearance changes don't walk unused widgets."""
        keep = self._current
        for name in list(self.panels):
            if name == keep:
                continue
            try:
                self.panels[name].destroy()
            except Exception:
                pass
            self.panels.pop(name, None)

    def _on_theme_selected(self, mode_label):
        # Debounce rapid menu picks; CustomTkinter restyles every live widget.
        if self._theme_job is not None:
            try:
                self.after_cancel(self._theme_job)
            except Exception:
                pass
        self.theme_menu.configure(state="disabled")
        self._theme_job = self.after(40, lambda m=mode_label: self._apply_appearance(m))

    def _apply_appearance(self, mode_label):
        self._theme_job = None
        if self._theme_busy:
            return
        self._theme_busy = True
        try:
            # Fewer widgets = snappier restyle.
            self._drop_inactive_panels()
            self.update_idletasks()
            ctk.set_appearance_mode(str(mode_label).lower())
            self.analytics.save_appearance(mode_label)
            self.update_idletasks()
        finally:
            self._theme_busy = False
            try:
                self.theme_menu.configure(state="normal")
            except Exception:
                pass

    def show(self, label):
        # Lazy-create, then show exactly one panel. grid_remove keeps layout stable.
        self._ensure_panel(label)
        for name, panel in self.panels.items():
            (panel.grid if name == label else panel.grid_remove)()
        self._current = label
        for name, btn in self.buttons.items():
            active = name == label
            btn.configure(
                fg_color=ACCENT if active else "transparent",
                hover_color=ACCENT_HOVER if active else ("#FFE9A8", BRAND_NAVY),
                text_color=ON_ACCENT_TEXT if active else IDLE_TEXT)
        self.analytics.track("open_panel", panel=label)


if __name__ == "__main__":
    # Slightly friendlier process name in Task Manager for frozen builds.
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            f"{DEV_NAME}.SecKit.{APP_VERSION}")
    except Exception:
        pass
    App().mainloop()
