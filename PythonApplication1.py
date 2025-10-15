# ops_shell.py
# Unified Operations Shell (ASCII only, no explicit encodings)
# ---------------------------------------------------------
# Tabs:
#   1) SEC OPS: Deep Single Target Inspector
#   2) Regex Search: Folder-based .txt regex search with highlights
#   3) File Tools: Selective Copy, Find Large Files, Renumber Files, Convert Dates
#   4) Builder: OneTouchBuilder for Windows installer creation
#   5) Link Verifier: Crawl links, filter by status, color-coded, and report grouping
#
# Auto Updater:
#   - Checks GitHub version.txt vs local version.txt
#   - Prompts user to update
#   - Backs up ops_shell.py to ops_shell_backup.py
#   - Updates ops_shell.py and requirements.txt
#   - Installs/updates dependencies
#   - Restarts app on success
#
# Requirements:
#   PySide6
#   requests
#   beautifulsoup4
#   cryptography
#   Pillow (optional, only for Builder icon conversion)
#
# Run:
#   python ops_shell.py

from pathlib import Path
import sys
import os
import threading
import socket
import ssl
import json
import datetime
import re
import csv
import shutil
import subprocess
import tempfile
import urllib.request
from urllib.parse import urljoin, urlparse

# optional Pillow for icon conversion (Builder)
try:
    from PIL import Image
except Exception:
    Image = None

# third-party
import requests
from bs4 import BeautifulSoup
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Qt
from PySide6 import QtCore, QtGui, QtWidgets


# ------------------------------
# Configuration / Versioning
# ------------------------------
GITHUB_REPO = "https://github.com/plgraham1/LCARS"
GITHUB_RAW = "https://raw.githubusercontent.com/plgraham1/LCARS/main/"
LOCAL_VERSION_FILE = "version.txt"
LOCAL_REQUIREMENTS = "requirements.txt"
LOCAL_SCRIPT = "ops_shell.py"


# ------------------------------
# Theme (neutral blue/gray)
# ------------------------------
class OpsTheme:
    BG = QtGui.QColor("#11161C")
    FG = QtGui.QColor("#E8EDF5")
    PANEL = QtGui.QColor("#1B222C")
    ACCENT = QtGui.QColor("#4A90E2")
    SUBACCENT = QtGui.QColor("#2E3B4A")

    BTN_AMBER = QtGui.QColor("#D89E3F")
    BTN_AMBER_HOVER = QtGui.QColor("#E8B45D")
    BTN_AMBER_ACTIVE = QtGui.QColor("#F5C469")

    TEXT_MUTED = QtGui.QColor("#B8C3D1")
    TEXT_DANGER = QtGui.QColor("#F27878")
    TEXT_OK = QtGui.QColor("#7FD3A2")


# ------------------------------
# Auto Updater (GUI, with backup)
# ------------------------------
def _read_local_version():
    try:
        with open(LOCAL_VERSION_FILE, "r") as f:
            return f.read().strip()
    except Exception:
        return "0.0.0"


def _get_remote_text(filename):
    try:
        r = requests.get(GITHUB_RAW + filename, timeout=10)
        if r.status_code == 200:
            return r.text
    except Exception:
        pass
    return None


def _compare_versions(local, remote):
    def normalize(v):
        parts = []
        for x in v.strip().split("."):
            try:
                parts.append(int(x))
            except Exception:
                parts.append(0)
        return parts
    try:
        return normalize(remote) > normalize(local)
    except Exception:
        return False


def _backup_file(path, backup_path):
    try:
        if os.path.exists(path):
            shutil.copy2(path, backup_path)
    except Exception:
        pass


def _download_and_replace_text_file(filename, remote_text):
    if remote_text is None:
        return False
    try:
        tmp = tempfile.NamedTemporaryFile(delete=False, mode="w")
        tmp.write(remote_text)
        tmp.close()
        shutil.copy(tmp.name, filename)
        os.remove(tmp.name)
        return True
    except Exception:
        return False


def _update_requirements(remote_text, parent=None):
    if remote_text is None:
        return
    try:
        write = True
        if os.path.exists(LOCAL_REQUIREMENTS):
            with open(LOCAL_REQUIREMENTS, "r") as f:
                local_text = f.read()
            if local_text.strip() == remote_text.strip():
                write = False
        if write:
            with open(LOCAL_REQUIREMENTS, "w") as f:
                f.write(remote_text.strip() + "\n")
        subprocess.call([sys.executable, "-m", "pip", "install", "-r", LOCAL_REQUIREMENTS, "--upgrade"])
    except Exception as e:
        QtWidgets.QMessageBox.warning(parent, "Updater", "Requirement update error: " + str(e))


def check_for_updates_gui(parent=None):
    local_ver = _read_local_version()
    remote_ver = _get_remote_text("version.txt")
    if not remote_ver:
        return
    remote_ver = remote_ver.strip()

    if _compare_versions(local_ver, remote_ver):
        msg = (
            "A new version is available.\n\n"
            "Current: " + local_ver + "\n"
            "Latest: " + remote_ver + "\n\n"
            "Do you want to update now?"
        )
        ans = QtWidgets.QMessageBox.question(parent, "Update Available", msg)
        if ans == QtWidgets.QMessageBox.Yes:
            remote_req = _get_remote_text("requirements.txt")
            remote_code = _get_remote_text("ops_shell.py")

            _backup_file(LOCAL_SCRIPT, "ops_shell_backup.py")

            if remote_code:
                if not _download_and_replace_text_file(LOCAL_SCRIPT, remote_code):
                    QtWidgets.QMessageBox.warning(parent, "Updater", "Failed to update main script.")
            if remote_req:
                _update_requirements(remote_req, parent)

            try:
                with open(LOCAL_VERSION_FILE, "w") as f:
                    f.write(remote_ver + "\n")
            except Exception:
                pass

            QtWidgets.QMessageBox.information(parent, "Updater", "Update complete. The application will now restart.")
            os.execv(sys.executable, [sys.executable] + sys.argv)


# ------------------------------
# Utilities
# ------------------------------
def stardate_like_now():
    now = datetime.datetime.now()
    day = now.timetuple().tm_yday
    frac = (now.hour * 3600 + now.minute * 60 + now.second) / 86400.0
    return str(now.year) + "." + f"{day:03d}" + str(int(frac * 10))


def human_readable_size(size_in_bytes):
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(size_in_bytes)
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            return f"{size:.2f} {unit}"
        size /= 1024.0


def is_windows():
    return os.name == "nt"


def exe_name(name):
    return name + ".exe" if is_windows() else name


def venv_paths(venv: Path):
    if is_windows():
        return venv / "Scripts" / "python.exe", venv / "Scripts" / "pip.exe"
    return venv / "bin" / "python", venv / "bin" / "pip"


def safe_app_name(script: Path):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", script.stem)


# ------------------------------
# Custom Widgets
# ------------------------------
class OpsButton(QtWidgets.QPushButton):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self._hover = False
        self._active = False
        self.setCursor(QtCore.Qt.PointingHandCursor)
        self.setMinimumHeight(44)
        self.setMinimumWidth(120)
        self.setCheckable(True)
        self.setStyleSheet("QPushButton { border: none; color: #0b0b0b; font-weight: 700; letter-spacing: 0.5px; }")

    def enterEvent(self, e):
        self._hover = True
        self.update()
        return super().enterEvent(e)

    def leaveEvent(self, e):
        self._hover = False
        self.update()
        return super().leaveEvent(e)

    def mousePressEvent(self, e):
        self._active = True
        self.update()
        return super().mousePressEvent(e)

    def mouseReleaseEvent(self, e):
        self._active = False
        self.update()
        return super().mouseReleaseEvent(e)

    def paintEvent(self, event):
        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.Antialiasing, True)
        rect = self.rect()
        radius = rect.height() / 2

        base = OpsTheme.BTN_AMBER
        if self._hover:
            base = OpsTheme.BTN_AMBER_HOVER
        if self._active or self.isChecked():
            base = OpsTheme.BTN_AMBER_ACTIVE

        path = QtGui.QPainterPath()
        path.addRoundedRect(rect.adjusted(2, 2, -2, -2), radius, radius)
        p.fillPath(path, base)

        p.setPen(QtGui.QColor("#0a0a0a"))
        font = p.font()
        font.setPointSizeF(max(11.0, rect.height() * 0.28))
        font.setWeight(QtGui.QFont.DemiBold)
        p.setFont(font)
        p.drawText(rect, QtCore.Qt.AlignCenter, self.text())
        p.end()


class OpsPanel(QtWidgets.QFrame):
    def __init__(self, color, title="", parent=None):
        super().__init__(parent)
        self._color = QtGui.QColor(color)
        self._title = title
        self.setMinimumHeight(40)

    def paintEvent(self, e):
        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.Antialiasing)

        rect = self.rect()
        r = min(rect.height(), 28)
        path = QtGui.QPainterPath()

        tl = rect.topLeft()
        tr = rect.topRight()
        bl = rect.bottomLeft()
        br = rect.bottomRight()

        path.moveTo(QtCore.QPointF(tr))
        path.lineTo(QtCore.QPointF(tl.x() + r, tl.y()))
        path.quadTo(QtCore.QPointF(tl), QtCore.QPointF(tl.x(), tl.y() + r))
        path.lineTo(QtCore.QPointF(bl.x(), bl.y() - r))
        path.quadTo(QtCore.QPointF(bl), QtCore.QPointF(bl.x() + r, bl.y()))
        path.lineTo(QtCore.QPointF(br))
        path.closeSubpath()

        p.fillPath(path, self._color)

        if self._title:
            p.setPen(QtGui.QColor("#0b0b0b"))
            f = p.font()
            f.setPointSize(12)
            f.setWeight(QtGui.QFont.Black)
            p.setFont(f)
            p.drawText(rect.adjusted(16, 0, -8, 0), QtCore.Qt.AlignVCenter | QtCore.Qt.AlignLeft, self._title)

        p.end()


# ------------------------------
# Layout: Sidebar, Header, Work Area
# ------------------------------
class Sidebar(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumWidth(220)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        self.titlePanel = OpsPanel(OpsTheme.ACCENT, title="Unified Operations Shell")
        layout.addWidget(self.titlePanel)

        self.buttons = []
        for label in ["SEC OPS", "Regex Search", "File Tools", "Builder", "Link Verifier"]:
            b = OpsButton(label)
            layout.addWidget(b)
            self.buttons.append(b)

        layout.addStretch(1)
        self.footerPanel = OpsPanel(OpsTheme.SUBACCENT, title="READY")
        layout.addWidget(self.footerPanel)


class Header(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(64)

        h = QtWidgets.QHBoxLayout(self)
        h.setContentsMargins(12, 12, 12, 0)
        h.setSpacing(10)

        self.left = OpsPanel(OpsTheme.SUBACCENT, title="SYSTEM")
        self.mid = OpsPanel(OpsTheme.PANEL, title="INTERFACE")
        self.right = OpsPanel(OpsTheme.PANEL)

        h.addWidget(self.left, 2)
        h.addWidget(self.mid, 2)

        self.clockLabel = QtWidgets.QLabel()
        self.clockLabel.setAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
        f = self.clockLabel.font()
        f.setPointSize(14)
        f.setWeight(QtGui.QFont.Black)
        self.clockLabel.setFont(f)
        self.clockLabel.setStyleSheet("color: #E8EDF5; padding-right: 8px;")

        self.right.setLayout(QtWidgets.QHBoxLayout())
        self.right.layout().setContentsMargins(12, 0, 12, 0)
        self.right.layout().addWidget(self.clockLabel)

        h.addWidget(self.right, 3)

        self._timer = QtCore.QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(1000)
        self._tick()

    @QtCore.Slot()
    def _tick(self):
        now = datetime.datetime.now().strftime("%H:%M:%S")
        self.clockLabel.setText(stardate_like_now() + "   |   " + now)


class WorkArea(QtWidgets.QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.setStyleSheet("background: " + OpsTheme.BG.name() + "; border: none;")
        v = QtWidgets.QVBoxLayout(self)
        v.setContentsMargins(12, 12, 12, 12)
        v.setSpacing(12)

        self.banner = OpsPanel(OpsTheme.PANEL, title="SECURITY CONSOLE")
        v.addWidget(self.banner)

        self.stack = QtWidgets.QStackedWidget()
        v.addWidget(self.stack, 1)

        placeholder = QtWidgets.QLabel("Select a function on the left.")
        placeholder.setAlignment(QtCore.Qt.AlignCenter)
        f = placeholder.font()
        f.setPointSize(18)
        f.setWeight(QtGui.QFont.DemiBold)
        placeholder.setFont(f)
        placeholder.setStyleSheet("color:#B8C3D1;padding:24px;")
        container = QtWidgets.QWidget()
        lay = QtWidgets.QVBoxLayout(container)
        lay.addWidget(placeholder, 1)
        self.stack.addWidget(container)

    def set_page(self, w, title, color):
        if self.stack.indexOf(w) == -1:
            self.stack.addWidget(w)
        self.stack.setCurrentWidget(w)
        self.banner._color = QtGui.QColor(color)
        self.banner._title = title
        self.banner.update()


# ------------------------------
# Main Window
# ------------------------------
class OpsWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Unified Operations Shell")
        self.resize(1300, 900)
        self.setStyleSheet("background: " + OpsTheme.BG.name() + "; color: " + OpsTheme.FG.name() + ";")

        central = QtWidgets.QWidget()
        self.setCentralWidget(central)

        layout = QtWidgets.QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.header = Header()
        layout.addWidget(self.header)

        body = QtWidgets.QHBoxLayout()
        body.setContentsMargins(0, 12, 0, 12)
        body.setSpacing(12)
        layout.addLayout(body, 1)

        self.sidebar = Sidebar()
        body.addWidget(self.sidebar)

        self.work = WorkArea()
        body.addWidget(self.work, 1)

        self._sec_ops = None
        self._regex = None
        self._filetools = None
        self._builder = None
        self._linkver = None

        QtGui.QShortcut(QtGui.QKeySequence("Ctrl+Q"), self, activated=self.close)
        QtGui.QShortcut(QtGui.QKeySequence("Esc"), self, activated=self.close)

        for b in self.sidebar.buttons:
            b.clicked.connect(lambda checked, btn=b: self._on_nav(btn))

    def _on_nav(self, btn):
        label = btn.text()
        for b in self.sidebar.buttons:
            b.setChecked(b is btn)

        if label == "SEC OPS":
            if self._sec_ops is None:
                self._sec_ops = SecOpsPanel()
            self.work.set_page(self._sec_ops, "SECURITY OPS", OpsTheme.PANEL)

        elif label == "Regex Search":
            if self._regex is None:
                self._regex = RegexPanel()
            self.work.set_page(self._regex, "REGEX SEARCH", OpsTheme.PANEL)

        elif label == "File Tools":
            if self._filetools is None:
                self._filetools = FileToolsPanel()
            self.work.set_page(self._filetools, "FILE TOOLS", OpsTheme.PANEL)

        elif label == "Builder":
            if self._builder is None:
                self._builder = BuilderPanel()
            self.work.set_page(self._builder, "BUILDER", OpsTheme.PANEL)

        elif label == "Link Verifier":
            if self._linkver is None:
                self._linkver = LinkVerifierPanel()
            self.work.set_page(self._linkver, "LINK VERIFIER", OpsTheme.PANEL)

        else:
            self.work.stack.setCurrentIndex(0)
            self.work.banner._title = label
            self.work.banner._color = OpsTheme.PANEL
            self.work.banner.update()


# ------------------------------
# SEC OPS Panel (Deep Inspector)
# ------------------------------
class SecOpsPanel(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.user_agent = "Mozilla/5.0"
        self.current_result = {}
        self.current_vuln = {}
        self.current_ports = []

        self.text_bg = "#1B222C"
        self.text_fg = "#E8EDF5"

        self._build_ui()

    def _build_ui(self):
        v = QtWidgets.QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(12)

        row = QtWidgets.QHBoxLayout()
        row.setSpacing(8)
        self.targetEdit = QtWidgets.QLineEdit()
        self.targetEdit.setPlaceholderText("Target (URL or host)")
        self.inspectBtn = OpsButton("INSPECT")
        self.vulnBtn = OpsButton("VULN CHECK")
        self.portBtn = OpsButton("SCAN PORTS")
        self.exportBtn = OpsButton("EXPORT JSON")
        for b in (self.inspectBtn, self.vulnBtn, self.portBtn, self.exportBtn):
            b.setChecked(False)
        row.addWidget(self.targetEdit, 1)
        row.addWidget(self.inspectBtn)
        row.addWidget(self.vulnBtn)
        row.addWidget(self.portBtn)
        row.addWidget(self.exportBtn)
        v.addLayout(row)

        stat = QtWidgets.QHBoxLayout()
        stat.setSpacing(8)
        self.statusLbl = QtWidgets.QLabel("Ready")
        self.statusLbl.setStyleSheet("color: #E8EDF5")
        self.progress = QtWidgets.QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.hide()
        stat.addWidget(self.statusLbl, 0)
        stat.addWidget(self.progress, 1)
        v.addLayout(stat)

        self.tabs = QtWidgets.QTabWidget()
        self.tabs.setStyleSheet(
            "QTabWidget::pane { border: 1px solid #2E3B4A; background: #11161C; }"
            "QTabBar::tab { background: #1B222C; color: #E8EDF5; padding: 6px 10px; margin-right: 2px; }"
            "QTabBar::tab:selected { background: #2A3542; color: #ffffff; }"
            "QTabBar::tab:hover { background: #24303D; }"
        )
        v.addWidget(self.tabs, 1)

        self.textAreas = {}
        for name in [
            "Overview", "Headers", "HTML", "Links", "Scripts",
            "Images", "Iframes", "Metadata", "Vulnerabilities",
            "Recommendations", "Ports"
        ]:
            w = QtWidgets.QWidget()
            l = QtWidgets.QVBoxLayout(w)
            l.setContentsMargins(6, 6, 6, 6)
            t = QtWidgets.QPlainTextEdit()
            t.setReadOnly(True)
            t.setStyleSheet("background: " + self.text_bg + "; color: " + self.text_fg + "; border: 1px solid #2E3B4A;")
            l.addWidget(t)
            self.tabs.addTab(w, name)
            self.textAreas[name] = t

        self.inspectBtn.clicked.connect(self.on_inspect)
        self.vulnBtn.clicked.connect(self.on_vuln_scan)
        self.portBtn.clicked.connect(self.on_port_scan)
        self.exportBtn.clicked.connect(self.on_export)

    def _setBusy(self, msg):
        self.statusLbl.setText(msg)
        self.progress.show()

    def _finish(self):
        self.progress.hide()
        self.statusLbl.setText("Done")

    def safe_join(self, base, href):
        try:
            return urljoin(base, href)
        except Exception:
            return href

    def scrape_static(self, url, user_agent, timeout=15):
        headers = {"User-Agent": user_agent}
        resp = requests.get(url, headers=headers, timeout=timeout)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")

        title = soup.title.string.strip() if soup.title and soup.title.string else "N/A"
        headings = [h.get_text(strip=True) for h in soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6"])]

        links = [self.safe_join(url, a.get("href")) for a in soup.find_all("a", href=True)]
        scripts = [self.safe_join(url, s.get("src")) for s in soup.find_all("script", src=True)]
        images = [self.safe_join(url, i.get("src")) for i in soup.find_all("img", src=True)]
        iframes = [self.safe_join(url, f.get("src")) for f in soup.find_all("iframe", src=True)]

        meta = {}
        for m in soup.find_all("meta"):
            name = m.get("name") or m.get("property") or m.get("http-equiv")
            content = m.get("content")
            if name and content:
                meta[name] = content

        return {
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "title": title,
            "headings": headings,
            "links": links,
            "scripts": scripts,
            "images": images,
            "iframes": iframes,
            "meta": meta,
            "html": resp.text
        }

    def missing_security_headers(self, headers):
        required = [
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
        ]
        lower = {k.lower(): v for k, v in headers.items()}
        return [h for h in required if h not in lower]

    def check_common_paths(self, base_url, user_agent, timeout=6):
        common = [
            "/admin/", "/administrator/", "/login/", "/wp-admin/", "/wp-login.php",
            "/phpmyadmin/", "/pma/", "/.git/", "/.env", "/config.php", "/admin.php",
            "/server-status", "/actuator", "/console", "/adminer.php"
        ]
        found = []
        hdr = {"User-Agent": user_agent}
        for pth in common:
            test = base_url.rstrip("/") + pth
            try:
                r = requests.get(test, headers=hdr, timeout=timeout, allow_redirects=True)
                if r.status_code < 400:
                    found.append({"url": test, "status": r.status_code})
            except Exception:
                pass
        return found

    def check_git_exposed(self, base_url, user_agent, timeout=6):
        try:
            r = requests.get(urljoin(base_url, "/.git/HEAD"), headers={"User-Agent": user_agent}, timeout=timeout)
            if r.status_code == 200 and "ref:" in r.text:
                return True, r.text.strip()
        except Exception:
            pass
        return False, ""

    def check_robots(self, base_url, user_agent, timeout=6):
        try:
            r = requests.get(urljoin(base_url, "/robots.txt"), headers={"User-Agent": user_agent}, timeout=timeout)
            if r.status_code == 200 and r.text.strip():
                return r.text.strip()
        except Exception:
            pass
        return None

    def parse_tls_certificate(self, hostname, port=443, timeout=6):
        info = {
            "valid": False,
            "expired": False,
            "subject": "",
            "issuer": "",
            "not_before": "",
            "not_after": "",
        }
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    der_cert = ssock.getpeercert(True)
                    cert = x509.load_der_x509_certificate(der_cert, default_backend())
                    info["subject"] = str(cert.subject.rfc4514_string())
                    info["issuer"] = str(cert.issuer.rfc4514_string())
                    info["not_before"] = str(cert.not_valid_before)
                    info["not_after"] = str(cert.not_valid_after)
                    info["valid"] = True
                    now = datetime.datetime.utcnow()
                    info["expired"] = cert.not_valid_after < now
                    info["tls_version"] = ssock.version()
        except Exception as e:
            info["error"] = str(e)
        return info

    def tcp_connect(self, host, port, timeout=0.6):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            s.close()
            return True
        except Exception:
            return False

    def scan_ports(self, host, start, end, timeout=0.6, max_threads=200):
        if start > end:
            start, end = end, start
        open_ports = []
        lock = threading.Lock()
        ports = list(range(start, end + 1))
        idx = {"i": 0}

        def worker():
            while True:
                with lock:
                    if idx["i"] >= len(ports):
                        return
                    p = ports[idx["i"]]
                    idx["i"] += 1
                if self.tcp_connect(host, p, timeout=timeout):
                    with lock:
                        open_ports.append(p)

        threads = []
        for _ in range(min(max_threads, len(ports))):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        open_ports.sort()
        return open_ports

    def generate_recommendations(self, vuln, open_ports):
        guide = {
            "strict-transport-security": "Enable HTTPS and add Strict-Transport-Security: max-age=31536000; includeSubDomains",
            "content-security-policy": "Add Content-Security-Policy to restrict allowed sources of scripts, styles, etc.",
            "x-frame-options": "Set X-Frame-Options: SAMEORIGIN to prevent clickjacking.",
            "x-content-type-options": "Set X-Content-Type-Options: nosniff to prevent MIME sniffing.",
            "referrer-policy": "Set Referrer-Policy: no-referrer-when-downgrade or stricter.",
            "permissions-policy": "Add Permissions-Policy to control browser features usage.",
            "git_exposed": "Block access to /.git paths in the web server and remove repository data from public hosts.",
            "common_paths": "Lock down default admin panels, require authentication, and disable directory listing.",
            "robots.txt": "Review robots.txt and remove sensitive paths or protect them by auth.",
            "open_ports": "Restrict unneeded ports using a firewall; prefer allowlists and TLS.",
            "tls_expired": "Renew TLS/SSL certificates before expiration to maintain secure connections.",
            "tls_insecure": "Use modern TLS versions (1.2 or higher) and disable weak ciphers.",
        }
        recs = []
        for h in vuln.get("missing_headers", []):
            if h in guide:
                recs.append(guide[h])
        if vuln.get("git_exposed", {}).get("exposed"):
            recs.append(guide["git_exposed"])
        if vuln.get("common_paths"):
            recs.append(guide["common_paths"])
        if vuln.get("robots_txt"):
            recs.append(guide["robots.txt"])
        if open_ports:
            recs.append(guide["open_ports"])
        tls = vuln.get("tls_info", {})
        if tls.get("expired"):
            recs.append(guide["tls_expired"])
        if tls.get("tls_version") and tls["tls_version"] not in ("TLSv1.2", "TLSv1.3"):
            recs.append(guide["tls_insecure"])
        if not recs:
            recs.append("No immediate remediation items detected.")
        return recs

    def on_inspect(self):
        target = self.targetEdit.text().strip()
        if not target:
            QtWidgets.QMessageBox.critical(self, "Inspect", "Enter target")
            return
        if not target.startswith("http"):
            target = "http://" + target
        for t in self.textAreas.values():
            t.setPlainText("")
        self._setBusy("Inspecting...")

        def run():
            try:
                data = self.scrape_static(target, self.user_agent)
                self.current_result = data
                QtCore.QMetaObject.invokeMethod(
                    self, "_fill_inspect", QtCore.Qt.QueuedConnection, QtCore.Q_ARG(str, target)
                )
            except Exception as e:
                QtCore.QMetaObject.invokeMethod(
                    self, "_show_error", QtCore.Qt.QueuedConnection, QtCore.Q_ARG(str, "Inspect: " + str(e))
                )

        threading.Thread(target=run, daemon=True).start()

    @QtCore.Slot(str)
    def _fill_inspect(self, target):
        data = self.current_result or {}
        self.textAreas["Overview"].setPlainText(
            "Target: " + target + "\nStatus: " + str(data.get("status_code")) + "\nTitle: " + str(data.get("title"))
        )
        self.textAreas["Headers"].setPlainText(
            "\n".join([k + ": " + str(v) for k, v in data.get("headers", {}).items()])
        )
        self.textAreas["HTML"].setPlainText((data.get("html", "") or "")[:50000])
        for key in ["Links", "Scripts", "Images", "Iframes"]:
            self.textAreas[key].setPlainText("\n".join(data.get(key.lower(), [])))
        self.textAreas["Metadata"].setPlainText(
            "\n".join([k + ": " + str(v) for k, v in data.get("meta", {}).items()])
        )
        self._finish()

    def on_vuln_scan(self):
        target = self.targetEdit.text().strip()
        if not target:
            QtWidgets.QMessageBox.critical(self, "Vuln", "Enter target")
            return
        if not target.startswith("http"):
            target = "http://" + target
        self.textAreas["Vulnerabilities"].setPlainText("")
        self.textAreas["Recommendations"].setPlainText("")
        self._setBusy("Scanning vulnerabilities...")

        def run():
            try:
                parsed = urlparse(target)
                base = parsed.scheme + "://" + parsed.netloc
                headers = self.current_result.get("headers", {}) if self.current_result else {}
                vuln = {
                    "missing_headers": self.missing_security_headers(headers),
                    "common_paths": self.check_common_paths(base, self.user_agent),
                    "git_exposed": {},
                    "robots_txt": self.check_robots(base, self.user_agent),
                    "tls_info": self.parse_tls_certificate(parsed.hostname)
                }
                exposed, head = self.check_git_exposed(base, self.user_agent)
                vuln["git_exposed"] = {"exposed": exposed, "head": head}
                self.current_vuln = vuln
                recs = self.generate_recommendations(vuln, self.current_ports)
                self._recs_cache = recs
                QtCore.QMetaObject.invokeMethod(self, "_fill_vuln", QtCore.Qt.QueuedConnection)
            except Exception as e:
                QtCore.QMetaObject.invokeMethod(
                    self, "_show_error", QtCore.Qt.QueuedConnection, QtCore.Q_ARG(str, "Vuln: " + str(e))
                )

        threading.Thread(target=run, daemon=True).start()

    @QtCore.Slot()
    def _fill_vuln(self):
        vuln = self.current_vuln or {}
        recs = getattr(self, "_recs_cache", [])
        lines = ["Missing Headers:"] + ["- " + h for h in vuln.get("missing_headers", [])]
        lines.append("\nTLS Info:\n" + json.dumps(vuln.get("tls_info", {}), indent=2)[:2000])
        self.textAreas["Vulnerabilities"].setPlainText("\n".join(lines))
        self.textAreas["Recommendations"].setPlainText("\n".join(["- " + r for r in recs]))
        self._finish()

    def on_port_scan(self):
        target = self.targetEdit.text().strip()
        if not target:
            QtWidgets.QMessageBox.critical(self, "Ports", "Enter target")
            return
        host = urlparse(target).hostname if target.startswith("http") else target
        self.textAreas["Ports"].setPlainText("")
        self._setBusy("Scanning ports...")

        def run():
            try:
                resolved = socket.gethostbyname(host)
                open_ports = self.scan_ports(resolved, 1, 1024)
                self.current_ports = open_ports
                self._ports_cache = (host, resolved, open_ports)
                QtCore.QMetaObject.invokeMethod(self, "_fill_ports", QtCore.Qt.QueuedConnection)
            except Exception as e:
                QtCore.QMetaObject.invokeMethod(
                    self, "_show_error", QtCore.Qt.QueuedConnection, QtCore.Q_ARG(str, "Ports: " + str(e))
                )

        threading.Thread(target=run, daemon=True).start()

    @QtCore.Slot()
    def _fill_ports(self):
        host, resolved, ports = getattr(self, "_ports_cache", ("", "", []))
        lines = ["Host: " + host + " (" + resolved + ")"]
        if not ports:
            lines.append("No open ports.")
        else:
            lines.append("Open Ports:")
            lines += ["- " + str(p) for p in ports]
        self.textAreas["Ports"].setPlainText("\n".join(lines))
        self._finish()

    @QtCore.Slot(str)
    def _show_error(self, msg):
        QtWidgets.QMessageBox.critical(self, "SEC OPS", msg)
        self._finish()

    def on_export(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export JSON", "", "JSON (*.json)")
        if not path:
            return
        bundle = {"static": self.current_result, "vuln": self.current_vuln, "ports": self.current_ports}
        with open(path, "w") as f:
            json.dump(bundle, f, indent=2)
        QtWidgets.QMessageBox.information(self, "Export", "Saved to " + path)


# ------------------------------
# Regex Search Panel
# ------------------------------
class RegexPanel(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.results = []  # list of {filename, line, text}
        self._build_ui()

    def _build_ui(self):
        v = QtWidgets.QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(12)

        row1 = QtWidgets.QHBoxLayout()
        row1.setSpacing(8)
        self.folderEdit = QtWidgets.QLineEdit()
        self.folderEdit.setPlaceholderText("Select folder containing .txt files")
        self.folderEdit.setReadOnly(True)
        self.pickBtn = OpsButton("Select Folder")
        row1.addWidget(self.folderEdit, 1)
        row1.addWidget(self.pickBtn)
        v.addLayout(row1)

        row2 = QtWidgets.QHBoxLayout()
        row2.setSpacing(8)
        self.regexEdit = QtWidgets.QLineEdit()
        self.regexEdit.setPlaceholderText("Enter regular expression...")
        self.recurseChk = QtWidgets.QCheckBox("Include subfolders")
        self.searchBtn = OpsButton("Search")
        self.searchBtn.setAutoDefault(True)
        self.exportBtn = OpsButton("Export Results")
        row2.addWidget(self.regexEdit, 1)
        row2.addWidget(self.recurseChk)
        row2.addWidget(self.searchBtn)
        row2.addWidget(self.exportBtn)
        v.addLayout(row2)

        self.regexEdit.returnPressed.connect(lambda: QtCore.QTimer.singleShot(0, self._run_search_safe))
        self.searchBtn.clicked.connect(lambda: QtCore.QTimer.singleShot(0, self._run_search_safe))

        stat = QtWidgets.QHBoxLayout()
        stat.setSpacing(8)
        self.statusLbl = QtWidgets.QLabel("Ready")
        self.statusLbl.setStyleSheet("color: #E8EDF5")
        self.progress = QtWidgets.QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.hide()
        stat.addWidget(self.statusLbl, 0)
        stat.addWidget(self.progress, 1)
        v.addLayout(stat)

        self.view = QtWidgets.QTextEdit()
        self.view.setReadOnly(True)
        self.view.setStyleSheet("background: #1B222C; color: #E8EDF5; border: 1px solid #2E3B4A;")
        v.addWidget(self.view, 1)

        self.pickBtn.clicked.connect(self._pick_folder)
        self.exportBtn.clicked.connect(self._on_export)

    def _pick_folder(self):
        path = QtWidgets.QFileDialog.getExistingDirectory(self, "Select Folder", "")
        if path:
            self.folderEdit.setText(path)

    def _setBusy(self, msg):
        self.statusLbl.setText(msg)
        self.progress.show()

    def _finish(self, msg="Done"):
        self.progress.hide()
        self.statusLbl.setText(msg)

    def _run_search_safe(self):
        QtWidgets.QApplication.processEvents()
        folder = str(self.folderEdit.text()).strip()
        pattern_input = str(self.regexEdit.text()).strip()

        if not folder:
            QtWidgets.QMessageBox.critical(self, "Regex Search", "Please select a folder.")
            return
        if not pattern_input:
            QtWidgets.QMessageBox.critical(self, "Regex Search", "Please enter a regular expression.")
            return

        try:
            pattern = re.compile(pattern_input)
        except re.error as e:
            QtWidgets.QMessageBox.critical(self, "Regex Search", "Invalid regular expression: " + str(e))
            return

        self.results = []
        self.view.clear()
        self._setBusy("Searching...")

        recurse = self.recurseChk.isChecked()

        def run():
            html_out = []
            try:
                files = []
                if recurse:
                    for root, dirs, fnames in os.walk(folder):
                        for fn in fnames:
                            if fn.lower().endswith(".txt"):
                                files.append(os.path.join(root, fn))
                else:
                    for fn in os.listdir(folder):
                        if fn.lower().endswith(".txt"):
                            files.append(os.path.join(folder, fn))

                for fpath in files:
                    fname = os.path.basename(fpath)
                    added_header = False
                    try:
                        with open(fpath, "r") as fh:
                            for idx, line in enumerate(fh, start=1):
                                if pattern.search(line):
                                    if not added_header:
                                        html_out.append("<div style='margin-top:10px;color:#E8EDF5'><b>[" + fname + "]</b></div>")
                                        added_header = True
                                    hl = self._highlight_line_html(line.rstrip("\n"), pattern)
                                    html_out.append("<pre style='margin:0;color:#E8EDF5'>Line " + str(idx) + ": " + hl + "</pre>")
                                    self.results.append({"filename": fname, "line": idx, "text": line.rstrip("\n")})
                    except Exception as fe:
                        html_out.append("<div style='color:#F27878'>Could not read " + fname + ": " + str(fe) + "</div>")

                html_final = "\n".join(html_out) if html_out else "<div style='color:#B8C3D1'>No matches found.</div>"
                QtCore.QMetaObject.invokeMethod(
                    self, "_set_results_html", QtCore.Qt.QueuedConnection, QtCore.Q_ARG(str, html_final)
                )
            except Exception as e:
                QtCore.QMetaObject.invokeMethod(
                    self, "_show_error", QtCore.Qt.QueuedConnection, QtCore.Q_ARG(str, str(e))
                )

        threading.Thread(target=run, daemon=True).start()

    def _highlight_line_html(self, line, pattern):
        spans = []
        last = 0
        for m in pattern.finditer(line):
            start, end = m.span()
            if start > last:
                spans.append(self._esc(line[last:start]))
            match_text = self._esc(line[start:end])
            spans.append("<span style='background:#F5C469;color:#111;padding:0 2px'>" + match_text + "</span>")
            last = end
        if last < len(line):
            spans.append(self._esc(line[last:]))
        return "".join(spans)

    def _esc(self, s):
        return (
            s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
        )

    @QtCore.Slot(str)
    def _set_results_html(self, html_str):
        self.view.setHtml(html_str)
        self._finish("Done")

    @QtCore.Slot(str)
    def _show_error(self, msg):
        QtWidgets.QMessageBox.critical(self, "Regex Search", msg)
        self._finish("Error")

    def _on_export(self):
        if not self.results:
            QtWidgets.QMessageBox.information(self, "Export", "No results to export.")
            return
        path, sel = QtWidgets.QFileDialog.getSaveFileName(self, "Export Results", "", "JSON (*.json);;Text (*.txt)")
        if not path:
            return
        try:
            if path.lower().endswith(".json"):
                with open(path, "w") as f:
                    json.dump(self.results, f, indent=2)
            else:
                with open(path, "w") as f:
                    current = None
                    for item in self.results:
                        if item["filename"] != current:
                            current = item["filename"]
                            f.write("[" + current + "]\n")
                        f.write("Line " + str(item["line"]) + ": " + item["text"] + "\n")
            QtWidgets.QMessageBox.information(self, "Export", "Saved to " + path)
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Export", str(e))


# ------------------------------
# File Tools Panel (existing tools; Image Downloader will be added in Part 2)
# ------------------------------
class ResultsDialog(QtWidgets.QDialog):
    def __init__(self, title, headers, rows, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(900, 500)
        v = QtWidgets.QVBoxLayout(self)
        v.setContentsMargins(12, 12, 12, 12)
        v.setSpacing(8)

        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(len(headers))
        self.table.setHorizontalHeaderLabels(headers)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setAlternatingRowColors(True)
        self.table.setStyleSheet(
            "QTableWidget { background:#1B222C; color:#E8EDF5; gridline-color:#2E3B4A; }"
            "QHeaderView::section { background:#2A3542; color:#E8EDF5; padding:4px; border:1px solid #2E3B4A; }"
            "QTableWidget::item:selected { background:#4A90E2; color:#0b0b0b; }"
        )
        self.table.setRowCount(len(rows))
        for r, row in enumerate(rows):
            for c, val in enumerate(row):
                it = QtWidgets.QTableWidgetItem(str(val))
                it.setFlags(it.flags() ^ QtCore.Qt.ItemIsEditable)
                self.table.setItem(r, c, it)
        self.table.resizeColumnsToContents()
        v.addWidget(self.table, 1)

        h = QtWidgets.QHBoxLayout()
        h.addStretch(1)
        self.saveBtn = QtWidgets.QPushButton("Save to CSV")
        self.closeBtn = QtWidgets.QPushButton("Close")
        h.addWidget(self.saveBtn)
        h.addWidget(self.closeBtn)
        v.addLayout(h)

        self.saveBtn.clicked.connect(lambda: self._save_csv(headers, rows))
        self.closeBtn.clicked.connect(self.accept)

    def _save_csv(self, headers, rows):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save Results As", "", "CSV (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(headers)
                for row in rows:
                    w.writerow(row)
            QtWidgets.QMessageBox.information(self, "Export Complete", "Results saved to:\n" + path)
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Export Failed", str(e))


class FileToolsPanel(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self):
        v = QtWidgets.QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(12)

        grid = QtWidgets.QGridLayout()
        grid.setContentsMargins(12, 0, 12, 0)
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(12)

        self.btnCopy = OpsButton("Selective Copy")
        self.btnLarge = OpsButton("Find Large Files")
        self.btnRenumber = OpsButton("Renumber Files")
        self.btnConvert = OpsButton("Convert Dates")
        # Part 2 will add: self.btnImgDL = OpsButton("Image Downloader")

        for b in (self.btnCopy, self.btnLarge, self.btnRenumber, self.btnConvert):
            b.setChecked(False)

        grid.addWidget(self.btnCopy, 0, 0)
        grid.addWidget(self.btnLarge, 0, 1)
        grid.addWidget(self.btnRenumber, 1, 0)
        grid.addWidget(self.btnConvert, 1, 1)
        # Part 2 will add a new row for Image Downloader

        v.addLayout(grid)
        v.addStretch(1)

        self.btnCopy.clicked.connect(self.selective_copy)
        self.btnLarge.clicked.connect(self.find_large_files)
        self.btnRenumber.clicked.connect(self.renumber_files)
        self.btnConvert.clicked.connect(self.convert_dates)
        # Part 2 will connect: self.btnImgDL.clicked.connect(self.open_image_downloader)

    def selective_copy(self):
        src = QtWidgets.QFileDialog.getExistingDirectory(self, "Select Source Folder")
        if not src:
            return
        dest = QtWidgets.QFileDialog.getExistingDirectory(self, "Select Destination Folder")
        if not dest:
            return
        ext, ok = QtWidgets.QInputDialog.getText(self, "File Extension", "Enter file extension (e.g., .jpg, .pdf):")
        if not ok or not ext.strip():
            return
        ext = ext.strip()

        copied = []
        for foldername, _, filenames in os.walk(src):
            for filename in filenames:
                if filename.lower().endswith(ext.lower()):
                    src_path = os.path.join(foldername, filename)
                    dest_path = os.path.join(dest, filename)
                    try:
                        if not os.path.exists(dest_path):
                            shutil.copy2(src_path, dest_path)
                            copied.append((filename, "Copied", src_path))
                        else:
                            copied.append((filename, "Skipped (Exists)", src_path))
                    except Exception as e:
                        copied.append((filename, "Error: " + str(e), src_path))

        self._show_results("Selective Copy Results", ["File", "Action", "Path"], copied)

    def find_large_files(self):
        src = QtWidgets.QFileDialog.getExistingDirectory(self, "Select Folder to Scan")
        if not src:
            return
        size_str, ok = QtWidgets.QInputDialog.getText(self, "Size Threshold", "Enter size threshold (default 100):", text="100")
        if not ok or not size_str.strip():
            return
        unit, ok2 = QtWidgets.QInputDialog.getItem(self, "Unit", "Choose unit:", ["KB", "MB", "GB"], 1, False)
        if not ok2:
            return

        try:
            size = int(size_str.strip())
        except ValueError:
            QtWidgets.QMessageBox.critical(self, "Find Large Files", "Size must be an integer.")
            return

        multiplier = {"KB": 1024, "MB": 1024 * 1024, "GB": 1024 * 1024 * 1024}[unit]
        threshold = size * multiplier

        found = []
        for foldername, _, filenames in os.walk(src):
            for filename in filenames:
                path = os.path.join(foldername, filename)
                try:
                    size_bytes = os.path.getsize(path)
                    if size_bytes > threshold:
                        found.append((filename, human_readable_size(size_bytes), path))
                except Exception:
                    pass

        self._show_results("Large Files Found", ["File", "Size", "Path"], found)

    def renumber_files(self):
        folder = QtWidgets.QFileDialog.getExistingDirectory(self, "Select Folder")
        if not folder:
            return
        prefix, ok1 = QtWidgets.QInputDialog.getText(self, "Prefix", "Enter filename prefix (e.g., spam):")
        if not ok1 or not prefix.strip():
            return
        ext, ok2 = QtWidgets.QInputDialog.getText(self, "Extension", "Enter file extension (e.g., .txt):")
        if not ok2 or not ext.strip():
            return
        prefix = prefix.strip()
        ext = ext.strip()

        files = []
        regex = re.compile(r"^" + re.escape(prefix) + r"(\d+)" + re.escape(ext) + r"$")
        for f in os.listdir(folder):
            m = regex.match(f)
            if m:
                try:
                    files.append((int(m.group(1)), f))
                except ValueError:
                    pass

        files.sort()
        expected = 1
        results = []
        for num, fname in files:
            full_path = os.path.join(folder, fname)
            if num != expected:
                new_name = prefix + str(expected).zfill(3) + ext
                try:
                    os.rename(full_path, os.path.join(folder, new_name))
                    results.append((fname, "Renamed to " + new_name, full_path))
                except Exception as e:
                    results.append((fname, "Error: " + str(e), full_path))
            else:
                results.append((fname, "OK", full_path))
            expected += 1

        self._show_results("Renumber Results", ["Original File", "Status", "Path"], results)

    def convert_dates(self):
        src = QtWidgets.QFileDialog.getExistingDirectory(self, "Select Folder to Scan")
        if not src:
            return
        date_pattern = re.compile(r"^(.*?)(\d{2})-(\d{2})-(\d{4})(.*?)$")

        renamed = []
        for foldername, _, filenames in os.walk(src):
            for filename in filenames:
                mo = date_pattern.search(filename)
                if mo:
                    before, mm, dd, yyyy, after = mo.groups()
                    euro_filename = before + dd + "-" + mm + "-" + yyyy + after
                    src_path = os.path.join(foldername, filename)
                    dest_path = os.path.join(foldername, euro_filename)
                    try:
                        shutil.move(src_path, dest_path)
                        renamed.append((filename, euro_filename, src_path))
                    except Exception as e:
                        renamed.append((filename, "Error: " + str(e), src_path))

        self._show_results("Date Conversion Results", ["Original File", "New File", "Path"], renamed)

    def _show_results(self, title, headers, rows):
        dlg = ResultsDialog(title, headers, rows, self)
        dlg.exec()
# ------------------------------------------------------------
# Image Downloader Subtool (inside FileToolsPanel)
# ------------------------------------------------------------

class ImageDownloaderWidget(QtWidgets.QWidget):
    """Embedded image downloader with threaded downloads, fallback crawler, and log output."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self):
        v = QtWidgets.QVBoxLayout(self)
        v.setContentsMargins(12, 12, 12, 12)
        v.setSpacing(8)

        form = QtWidgets.QGridLayout()
        form.setHorizontalSpacing(8)
        form.setVerticalSpacing(6)

        self.urlEdit = QtWidgets.QLineEdit()
        self.urlEdit.setPlaceholderText(
            "Enter Imgur album URL, direct image URL, or site (e.g. https://www.nic.edu)"
        )

        self.folderBtn = OpsButton("Select Output Folder")
        self.folderEdit = QtWidgets.QLineEdit()
        self.folderEdit.setReadOnly(True)

        self.threadLabel = QtWidgets.QLabel("Threads:")
        self.threadSpin = QtWidgets.QSpinBox()
        self.threadSpin.setRange(1, 50)
        self.threadSpin.setValue(10)

        self.depthLabel = QtWidgets.QLabel("Max pages to scan:")
        self.depthSpin = QtWidgets.QSpinBox()
        self.depthSpin.setRange(1, 10)
        self.depthSpin.setValue(3)

        self.startBtn = OpsButton("Start Download")

        form.addWidget(QtWidgets.QLabel("Source:"), 0, 0)
        form.addWidget(self.urlEdit, 0, 1, 1, 4)
        form.addWidget(QtWidgets.QLabel("Output:"), 1, 0)
        form.addWidget(self.folderEdit, 1, 1, 1, 3)
        form.addWidget(self.folderBtn, 1, 4)
        form.addWidget(self.threadLabel, 2, 0)
        form.addWidget(self.threadSpin, 2, 1)
        form.addWidget(self.depthLabel, 2, 2)
        form.addWidget(self.depthSpin, 2, 3)
        form.addWidget(self.startBtn, 2, 4)
        v.addLayout(form)

        self.log = QtWidgets.QTextEdit()
        self.log.setReadOnly(True)
        self.log.setStyleSheet(
            "background:#1B222C;color:#E8EDF5;border:1px solid #2E3B4A;"
        )
        v.addWidget(self.log, 1)

        self.folderBtn.clicked.connect(self._pick_folder)
        self.startBtn.clicked.connect(self._start_downloads)

    def _pick_folder(self):
        path = QtWidgets.QFileDialog.getExistingDirectory(self, "Select Output Folder", "")
        if path:
            self.folderEdit.setText(path)

    def _append_log(self, msg, color="#E8EDF5"):
        self.log.append("<span style='color:%s'>%s</span>" % (color, msg))

    def _start_downloads(self):
        src = self.urlEdit.text().strip()
        dest = self.folderEdit.text().strip()
        threads = self.threadSpin.value()
        depth = self.depthSpin.value()

        if not src:
            QtWidgets.QMessageBox.warning(self, "Image Downloader", "Please enter a URL or file path.")
            return
        if not dest:
            now = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            dest = os.path.join(os.getcwd(), "downloads_" + now)
            os.makedirs(dest, exist_ok=True)
            self.folderEdit.setText(dest)

        self.log.clear()
        self._append_log(
            f"Starting downloads with {threads} threads (max {depth} pages to scan)...",
            color="#7FD3A2",
        )

        t = threading.Thread(target=self._run_downloads, args=(src, dest, threads, depth), daemon=True)
        t.start()

    # ------------------------------------------------------------------
    # Core worker
    # ------------------------------------------------------------------
    def _run_downloads(self, src, dest, threads, depth):
        urls = []

        # If user provided a file of URLs
        if os.path.isfile(src):
            try:
                with open(src, "r") as f:
                    urls = [line.strip() for line in f if line.strip()]
            except Exception as e:
                self._append_log("Error reading file list: " + str(e), "#F27878")
                return
        else:
            urls.append(src)

        # Handle Imgur album
        if any("imgur.com/a/" in u or "imgur.com/gallery/" in u for u in urls):
            urls = self._extract_imgur_images(urls)

        # Crawl fallback for general websites
        if len(urls) == 1 and not any(x in urls[0] for x in ("imgur.com", ".jpg", ".png", ".gif", ".webp")):
            self._append_log("No direct image links detected, starting crawler...", "#D89E3F")
            urls = self._crawl_site(urls[0], depth)

        # Filter and download
        valid_ext = (".jpg", ".jpeg", ".png", ".gif", ".webp")
        urls = [u for u in urls if any(x in u.lower() for x in valid_ext)]
        if not urls:
            self._append_log("No valid image URLs found.", "#F27878")
            return

        self._append_log(f"Found {len(urls)} image URLs. Beginning downloads...")

        report_path = os.path.join(dest, "report.txt")
        report = []
        lock = threading.Lock()
        q = {"i": 0}
        total = len(urls)

        def worker():
            while True:
                with lock:
                    if q["i"] >= total:
                        return
                    i = q["i"]
                    q["i"] += 1
                url = urls[i]
                name = os.path.basename(urlparse(url).path)
                out_path = os.path.join(dest, name)
                try:
                    if os.path.exists(out_path):
                        with lock:
                            self._append_log("[Skip] " + name, "#D89E3F")
                            report.append((name, "Skipped"))
                        continue
                    r = requests.get(url, stream=True, timeout=15)
                    if r.status_code == 200:
                        with open(out_path, "wb") as f:
                            for chunk in r.iter_content(8192):
                                f.write(chunk)
                        with lock:
                            self._append_log("[OK] " + name, "#7FD3A2")
                            report.append((name, "OK"))
                    else:
                        with lock:
                            self._append_log("[Fail] " + name + f" ({r.status_code})", "#F27878")
                            report.append((name, "HTTP " + str(r.status_code)))
                except Exception as e:
                    with lock:
                        self._append_log("[Err] " + name + " " + str(e), "#F27878")
                        report.append((name, "Error: " + str(e)))

        threads_list = []
        for _ in range(min(threads, len(urls))):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads_list.append(t)
        for t in threads_list:
            t.join()

        with open(report_path, "w") as f:
            for name, status in report:
                f.write(f"{name}\t{status}\n")

        self._append_log(f"Report written to {report_path}", "#7FD3A2")

        try:
            if is_windows():
                os.startfile(dest)
            elif sys.platform == "darwin":
                subprocess.call(["open", dest])
            else:
                subprocess.call(["xdg-open", dest])
        except Exception:
            pass

        self._append_log("Download complete.", "#7FD3A2")

    # ------------------------------------------------------------------
    # Support functions
    # ------------------------------------------------------------------
    def _extract_imgur_images(self, urls):
        all_imgs = []
        for u in urls:
            try:
                r = requests.get(u, timeout=10)
                soup = BeautifulSoup(r.text, "html.parser")
                imgs = soup.find_all("img")
                for img in imgs:
                    src = img.get("src")
                    if src:
                        if src.startswith("//"):
                            src = "https:" + src
                        elif src.startswith("/"):
                            src = "https://imgur.com" + src
                        if any(ext in src.lower() for ext in (".jpg", ".png", ".gif", ".webp")):
                            all_imgs.append(src)
            except Exception as e:
                self._append_log("Imgur parse error: " + str(e), "#F27878")
        return list(dict.fromkeys(all_imgs))

    def _crawl_site(self, base_url, depth):
        """Crawl within the same domain up to 'depth' pages and collect image URLs."""
        seen = set()
        found_imgs = []
        domain = urlparse(base_url).netloc
        queue = [base_url]

        for _ in range(depth):
            new_queue = []
            for url in queue:
                if url in seen:
                    continue
                seen.add(url)
                self._append_log("[Scan] " + url, "#D89E3F")
                try:
                    r = requests.get(url, timeout=10)
                    soup = BeautifulSoup(r.text, "html.parser")
                    imgs = [urljoin(url, img.get("src")) for img in soup.find_all("img", src=True)]
                    found_imgs.extend(imgs)
                    links = [urljoin(url, a.get("href")) for a in soup.find_all("a", href=True)]
                    for l in links:
                        if urlparse(l).netloc == domain and l not in seen and any(
                            not l.endswith(ext) for ext in (".jpg", ".png", ".gif", ".webp")
                        ):
                            new_queue.append(l)
                except Exception as e:
                    self._append_log("Crawl error: " + str(e), "#F27878")
            queue = new_queue

        return list(dict.fromkeys(found_imgs))

# ------------------------------------------------------------
# Integrate Image Downloader into FileToolsPanel
# ------------------------------------------------------------

def add_image_downloader_to_filetools():
    def open_image_downloader(self):
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle("Image Downloader")
        dlg.resize(700, 500)
        v = QtWidgets.QVBoxLayout(dlg)
        widget = ImageDownloaderWidget(dlg)
        v.addWidget(widget)
        dlg.exec()

    FileToolsPanel.open_image_downloader = open_image_downloader
    old_build_ui = FileToolsPanel._build_ui

    def new_build_ui(self):
        old_build_ui(self)
        # Add button to layout
        grid = self.layout().itemAt(0)
        if isinstance(grid, QtWidgets.QGridLayout):
            self.btnImgDL = OpsButton("Image Downloader")
            grid.addWidget(self.btnImgDL, 2, 0)
            self.btnImgDL.clicked.connect(self.open_image_downloader)

    FileToolsPanel._build_ui = new_build_ui

add_image_downloader_to_filetools()


# ------------------------------------------------------------
# Builder Panel
# ------------------------------------------------------------

class BuilderPanel(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        v = QtWidgets.QVBoxLayout(self)
        v.setContentsMargins(12, 12, 12, 12)
        v.setSpacing(8)

        self.info = QtWidgets.QLabel(
            "OneTouch Builder converts your Python app into a Windows EXE using PyInstaller.\n"
            "Select script, optional icon, and output folder."
        )
        self.info.setStyleSheet("color:#E8EDF5;")
        v.addWidget(self.info)

        form = QtWidgets.QGridLayout()
        form.setSpacing(8)

        self.scriptEdit = QtWidgets.QLineEdit()
        self.iconEdit = QtWidgets.QLineEdit()
        self.outEdit = QtWidgets.QLineEdit()

        self.pickScript = OpsButton("Script")
        self.pickIcon = OpsButton("Icon")
        self.pickOut = OpsButton("Output")
        self.buildBtn = OpsButton("Build")

        form.addWidget(QtWidgets.QLabel("Script:"), 0, 0)
        form.addWidget(self.scriptEdit, 0, 1)
        form.addWidget(self.pickScript, 0, 2)
        form.addWidget(QtWidgets.QLabel("Icon:"), 1, 0)
        form.addWidget(self.iconEdit, 1, 1)
        form.addWidget(self.pickIcon, 1, 2)
        form.addWidget(QtWidgets.QLabel("Output:"), 2, 0)
        form.addWidget(self.outEdit, 2, 1)
        form.addWidget(self.pickOut, 2, 2)
        v.addLayout(form)

        v.addWidget(self.buildBtn)
        v.addStretch(1)

        self.pickScript.clicked.connect(self._pick_script)
        self.pickIcon.clicked.connect(self._pick_icon)
        self.pickOut.clicked.connect(self._pick_out)
        self.buildBtn.clicked.connect(self._build_exe)

    def _pick_script(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select Script", "", "Python Files (*.py)")
        if path:
            self.scriptEdit.setText(path)

    def _pick_icon(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select Icon", "", "ICO Files (*.ico)")
        if path:
            self.iconEdit.setText(path)

    def _pick_out(self):
        path = QtWidgets.QFileDialog.getExistingDirectory(self, "Select Output Folder", "")
        if path:
            self.outEdit.setText(path)

    def _build_exe(self):
        script = self.scriptEdit.text().strip()
        outdir = self.outEdit.text().strip() or os.getcwd()
        icon = self.iconEdit.text().strip()
        if not script:
            QtWidgets.QMessageBox.warning(self, "Builder", "Select a Python script first.")
            return

        exe = exe_name(safe_app_name(Path(script)))
        cmd = [sys.executable, "-m", "PyInstaller", "--onefile", "-n", exe, "--distpath", outdir]
        if icon:
            cmd += ["--icon", icon]
        cmd += [script]

        dlg = QtWidgets.QMessageBox(self)
        dlg.setWindowTitle("Builder")
        dlg.setText("Building executable... this may take a while.\n\nCommand:\n" + " ".join(cmd))
        dlg.show()
        threading.Thread(target=lambda: subprocess.call(cmd), daemon=True).start()


# ------------------------------------------------------------
# Link Verifier Panel
# ------------------------------------------------------------

class LinkVerifierPanel(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        v = QtWidgets.QVBoxLayout(self)
        v.setContentsMargins(12, 12, 12, 12)
        v.setSpacing(8)

        row = QtWidgets.QHBoxLayout()
        row.setSpacing(8)
        self.urlEdit = QtWidgets.QLineEdit()
        self.urlEdit.setPlaceholderText("Enter base URL to crawl")
        self.startBtn = OpsButton("Start")
        row.addWidget(self.urlEdit, 1)
        row.addWidget(self.startBtn)
        v.addLayout(row)

        self.text = QtWidgets.QTextEdit()
        self.text.setReadOnly(True)
        self.text.setStyleSheet("background:#1B222C;color:#E8EDF5;border:1px solid #2E3B4A;")
        v.addWidget(self.text, 1)

        self.startBtn.clicked.connect(self._start)

    def _append(self, msg, color="#E8EDF5"):
        self.text.append("<span style='color:%s'>%s</span>" % (color, msg))

    def _start(self):
        base = self.urlEdit.text().strip()
        if not base:
            QtWidgets.QMessageBox.warning(self, "Link Verifier", "Enter a URL.")
            return
        if not base.startswith("http"):
            base = "http://" + base

        self.text.clear()
        threading.Thread(target=self._crawl, args=(base,), daemon=True).start()

    def _crawl(self, base):
        try:
            r = requests.get(base, timeout=10)
            soup = BeautifulSoup(r.text, "html.parser")
            links = [urljoin(base, a.get("href")) for a in soup.find_all("a", href=True)]
            links = list(dict.fromkeys(links))
            self._append("Found " + str(len(links)) + " links.")
        except Exception as e:
            self._append("Error loading page: " + str(e), "#F27878")
            return

        results = []
        lock = threading.Lock()
        q = {"i": 0}
        total = len(links)

        def worker():
            while True:
                with lock:
                    if q["i"] >= total:
                        return
                    i = q["i"]
                    q["i"] += 1
                url = links[i]
                try:
                    r = requests.head(url, timeout=6, allow_redirects=True)
                    code = r.status_code
                    color = "#7FD3A2" if code < 400 else "#F27878"
                    with lock:
                        self._append("[%s] %s" % (code, url), color)
                        results.append((url, code))
                except Exception as e:
                    with lock:
                        self._append("[Err] %s %s" % (url, e), "#F27878")
                        results.append((url, "Error"))

        threads = []
        for _ in range(min(10, total)):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

        report_path = os.path.join(os.getcwd(), "link_report.txt")
        try:
            with open(report_path, "w") as f:
                for url, code in results:
                    f.write(str(code) + "\t" + url + "\n")
            self._append("Report saved to " + report_path, "#7FD3A2")
        except Exception as e:
            self._append("Failed to save report: " + str(e), "#F27878")


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main():
    app = QtWidgets.QApplication(sys.argv)
    win = OpsWindow()
    win.show()
    check_for_updates_gui(win)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
