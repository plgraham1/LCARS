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
# File Tools Panel
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

        for b in (self.btnCopy, self.btnLarge, self.btnRenumber, self.btnConvert):
            b.setChecked(False)

        grid.addWidget(self.btnCopy, 0, 0)
        grid.addWidget(self.btnLarge, 0, 1)
        grid.addWidget(self.btnRenumber, 1, 0)
        grid.addWidget(self.btnConvert, 1, 1)

        v.addLayout(grid)
        v.addStretch(1)

        self.btnCopy.clicked.connect(self.selective_copy)
        self.btnLarge.clicked.connect(self.find_large_files)
        self.btnRenumber.clicked.connect(self.renumber_files)
        self.btnConvert.clicked.connect(self.convert_dates)

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


# ------------------------------
# Builder Panel (OneTouchBuilder)
# ------------------------------
class BuilderWorker(QtCore.QObject):
    log_signal = QtCore.Signal(str)
    done_signal = QtCore.Signal(bool, str)

    def __init__(self, script, req, icon, outdir):
        super().__init__()
        self.script = Path(script)
        self.req = Path(req)
        self.icon = icon
        self.outdir = Path(outdir)

    def _log(self, msg):
        self.log_signal.emit(msg)

    def preflight_checks(self):
        min_python = (3, 9)
        if sys.version_info < min_python:
            raise RuntimeError("Python 3.9+ required.")
        stat = shutil.disk_usage(Path.cwd())
        free_mb = stat.free // (1024 * 1024)
        if free_mb < 500:
            raise RuntimeError("Not enough disk space (" + str(free_mb) + "MB free, need 500MB).")
        try:
            urllib.request.urlopen("https://pypi.org", timeout=5)
        except Exception:
            raise RuntimeError("Internet connection required.")
        self._log("[*] Preflight checks passed.")

    def find_inno_iscc(self):
        candidates = []
        for base in [Path("C:/Program Files (x86)"), Path("C:/Program Files")]:
            if base.exists():
                for sub in base.glob("Inno Setup*"):
                    exe = sub / "ISCC.exe"
                    if exe.exists():
                        candidates.append(exe)
        return candidates[0] if candidates else None

    def download_and_install_inno_silent(self, tmp_dir: Path):
        url = "https://files.jrsoftware.org/is/6/innosetup-6.2.2.exe"
        installer = tmp_dir / "innosetup_installer.exe"
        self._log("[*] Downloading Inno Setup ...")
        try:
            urllib.request.urlretrieve(url, installer)
        except Exception as e:
            raise RuntimeError("Failed to download Inno Setup: " + str(e))
        self._log("[*] Running Inno Setup silent install ...")
        try:
            subprocess.check_call([str(installer), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-"])
        except Exception as e:
            raise RuntimeError("Inno Setup silent install failed: " + str(e))
        exe = self.find_inno_iscc()
        if not exe:
            raise RuntimeError("Inno Setup installed but ISCC.exe not found.")
        self._log("[*] Inno Setup available at " + str(exe))
        return exe

    def ensure_inno_iscc(self, out_dir: Path):
        exe = self.find_inno_iscc()
        if exe:
            self._log("[*] Found Inno Setup: " + str(exe))
            return exe
        return self.download_and_install_inno_silent(out_dir)

    def ensure_ico(self, icon_path, work_dir: Path):
        if not icon_path:
            return None
        p = Path(icon_path)
        if not p.exists():
            self._log("[!] Icon file not found, skipping icon.")
            return None
        if p.suffix.lower() == ".ico":
            return str(p)
        if Image is None:
            self._log("[!] Pillow not installed, cannot convert image to .ico. Continue without icon.")
            return None
        try:
            out = work_dir / (p.stem + ".ico")
            img = Image.open(p)
            img.save(out, format="ICO")
            self._log("[*] Converted icon to " + str(out))
            return str(out)
        except Exception as e:
            self._log("[!] Failed to convert icon: " + str(e))
            return None

    def write_inno_script(self, app_name, exe_path: Path, out_dir: Path, icon_path):
        output_dir = str(out_dir).replace("\\", "\\\\")
        iss_lines = [
            '#define MyAppName "' + app_name + '"',
            '#define MyAppExeName "' + exe_path.name + '"',
            "",
            "[Setup]",
            "AppName={#MyAppName}",
            "AppVersion=1.0",
            "DefaultDirName={pf}\\" + app_name,
            "DefaultGroupName=" + app_name,
            "UninstallDisplayIcon={app}\\{#MyAppExeName}",
            'OutputDir="' + output_dir + '"',
            "OutputBaseFilename=" + app_name + "_Installer",
            "Compression=lzma",
            "SolidCompression=yes",
            'SetupIconFile="' + icon_path + '"' if icon_path else "",
            "",
            "[Files]",
            'Source: "' + str(exe_path) + '"; DestDir: "{app}"; Flags: ignoreversion',
            "",
            "[Icons]",
            'Name: "{group}\\' + app_name + '"; Filename: "{app}\\{#MyAppExeName}"',
            'Name: "{commondesktop}\\' + app_name + '"; Filename: "{app}\\{#MyAppExeName}"; Tasks: desktopicon',
            "",
            "[Tasks]",
            'Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked',
            "",
            "[Run]",
            'Filename: "{app}\\{#MyAppExeName}"; Description: "Launch ' + app_name + '"; Flags: nowait postinstall skipifsilent',
        ]
        iss_path = out_dir / (app_name + ".iss")
        iss_path.write_text("\n".join([l for l in iss_lines if l.strip()]))
        return iss_path

    def install_requirements(self, requirements_file: Path, pip: Path):
        if not requirements_file or not requirements_file.exists():
            raise RuntimeError("Requirements file is required and must exist.")
        self._log("[*] Installing dependencies from " + str(requirements_file) + " ...")
        try:
            subprocess.check_call([str(pip), "install", "-r", str(requirements_file)])
            self._log("[*] Dependencies installed.")
        except Exception as e:
            raise RuntimeError("Failed to install dependencies: " + str(e))

    @QtCore.Slot()
    def run(self):
        try:
            self.outdir.mkdir(parents=True, exist_ok=True)
            work_dir = self.outdir / "work"
            if work_dir.exists():
                shutil.rmtree(work_dir)
            work_dir.mkdir(parents=True, exist_ok=True)

            self.preflight_checks()

            venv = work_dir / "build_env"
            self._log("[*] Creating virtual environment ...")
            subprocess.check_call([sys.executable, "-m", "venv", str(venv)])
            python, pip = venv_paths(venv)

            self._log("[*] Installing PyInstaller ...")
            subprocess.check_call([str(pip), "install", "pyinstaller"])

            self.install_requirements(self.req, pip)

            icon_final = self.ensure_ico(self.icon, work_dir) if self.icon else None

            dist_dir = work_dir / "dist"
            cmd = [
                str(python), "-m", "PyInstaller",
                "--onefile",
                "--noconfirm",
                "--distpath=" + str(dist_dir),
                str(self.script)
            ]
            if icon_final:
                cmd.append("--icon=" + icon_final)

            self._log("[*] Running PyInstaller ...")
            self._log("    " + " ".join(cmd))
            subprocess.check_call(cmd)

            exe_built = dist_dir / exe_name(self.script.stem)
            if not exe_built.exists():
                raise RuntimeError("PyInstaller completed but exe was not found.")

            self._log("[+] Built exe at " + str(exe_built))

            iscc = self.ensure_inno_iscc(self.outdir)
            app_name = safe_app_name(self.script)
            iss = self.write_inno_script(app_name, exe_built, self.outdir, icon_final or "")

            self._log("[*] Compiling installer with Inno Setup ...")
            subprocess.check_call([str(iscc), str(iss)], cwd=str(self.outdir))

            installer_path = self.outdir / (app_name + "_Installer.exe")
            if not installer_path.exists():
                raise RuntimeError("Inno Setup finished but installer not found.")

            self._log("[+] Installer created: " + str(installer_path))

            try:
                shutil.rmtree(work_dir)
                self._log("[*] Cleaned intermediate build files.")
            except Exception as e:
                self._log("[!] Cleanup error: " + str(e))

            self.done_signal.emit(True, str(installer_path))
        except Exception as e:
            self._log("[!] Error: " + str(e))
            self.done_signal.emit(False, str(e))


class BuilderPanel(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()
        self.worker_thread = None
        self.worker = None

    def _build_ui(self):
        v = QtWidgets.QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(8)

        form = QtWidgets.QGridLayout()
        form.setContentsMargins(12, 12, 12, 0)
        form.setHorizontalSpacing(8)
        form.setVerticalSpacing(8)

        self.scriptEdit = QtWidgets.QLineEdit()
        self.iconEdit = QtWidgets.QLineEdit()
        self.outEdit = QtWidgets.QLineEdit(str(Path.cwd() / "build_output"))
        self.reqEdit = QtWidgets.QLineEdit()

        bScript = QtWidgets.QPushButton("Browse")
        bIcon = QtWidgets.QPushButton("Browse")
        bOut = QtWidgets.QPushButton("Browse")
        bReq = QtWidgets.QPushButton("Browse")

        form.addWidget(QtWidgets.QLabel("Script:"), 0, 0)
        form.addWidget(self.scriptEdit, 0, 1)
        form.addWidget(bScript, 0, 2)

        form.addWidget(QtWidgets.QLabel("Icon:"), 1, 0)
        form.addWidget(self.iconEdit, 1, 1)
        form.addWidget(bIcon, 1, 2)

        form.addWidget(QtWidgets.QLabel("Output Dir:"), 2, 0)
        form.addWidget(self.outEdit, 2, 1)
        form.addWidget(bOut, 2, 2)

        form.addWidget(QtWidgets.QLabel("Requirements:"), 3, 0)
        form.addWidget(self.reqEdit, 3, 1)
        form.addWidget(bReq, 3, 2)

        v.addLayout(form)

        self.buildBtn = OpsButton("Build Installer")
        self.buildBtn.setChecked(False)
        v.addWidget(self.buildBtn, 0, QtCore.Qt.AlignLeft)

        self.logView = QtWidgets.QTextEdit()
        self.logView.setReadOnly(True)
        self.logView.setStyleSheet("background:#1B222C; color:#E8EDF5; border:1px solid #2E3B4A;")
        v.addWidget(self.logView, 1)

        bScript.clicked.connect(self._browse_script)
        bIcon.clicked.connect(self._browse_icon)
        bOut.clicked.connect(self._browse_out)
        bReq.clicked.connect(self._browse_req)
        self.buildBtn.clicked.connect(self._start_build)

    def _browse_script(self):
        p, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select Python Script", "", "Python (*.py)")
        if p:
            self.scriptEdit.setText(p)

    def _browse_icon(self):
        p, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select Icon", "", "Images (*.ico *.png *.jpg *.jpeg)")
        if p:
            self.iconEdit.setText(p)

    def _browse_out(self):
        p = QtWidgets.QFileDialog.getExistingDirectory(self, "Select Output Directory", "")
        if p:
            self.outEdit.setText(p)

    def _browse_req(self):
        p, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select requirements.txt", "", "Text (*.txt)")
        if p:
            self.reqEdit.setText(p)

    def _append_log(self, msg):
        self.logView.append(msg)
        self.logView.moveCursor(QtGui.QTextCursor.End)

    def _start_build(self):
        script = self.scriptEdit.text().strip()
        req = self.reqEdit.text().strip()
        icon = self.iconEdit.text().strip()
        outd = self.outEdit.text().strip()

        if not script:
            QtWidgets.QMessageBox.critical(self, "Builder", "Please select a Python script.")
            return
        if not req:
            QtWidgets.QMessageBox.critical(self, "Builder", "Please select a requirements.txt file.")
            return

        self.logView.clear()
        self._append_log("[*] Starting build ...")

        self.worker = BuilderWorker(script, req, icon, outd)
        self.worker_thread = QtCore.QThread(self)
        self.worker.moveToThread(self.worker_thread)

        self.worker_thread.started.connect(self.worker.run)
        self.worker.log_signal.connect(self._append_log)
        self.worker.done_signal.connect(self._build_finished)

        self.worker.done_signal.connect(self.worker_thread.quit)
        self.worker_thread.finished.connect(self.worker.deleteLater)
        self.worker_thread.finished.connect(self.worker_thread.deleteLater)

        self.worker_thread.start()

    @QtCore.Slot(bool, str)
    def _build_finished(self, ok, msg):
        if ok:
            QtWidgets.QMessageBox.information(self, "Builder", "Installer built:\n" + msg)
        else:
            QtWidgets.QMessageBox.critical(self, "Builder", msg)


# ------------------------------
# Link Verifier Panel (with filters and colors)
# ------------------------------
class LinkVerifierPanel(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._stop = False
        self.results = []  # list of dicts: {"url", "code", "category", "final_url"}
        self._build_ui()

    def _build_ui(self):
        v = QtWidgets.QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(12)

        row = QtWidgets.QHBoxLayout()
        row.setSpacing(8)
        self.urlEdit = QtWidgets.QLineEdit()
        self.urlEdit.setPlaceholderText("Enter starting URL (e.g., http://example.com)")
        self.depthSpin = QtWidgets.QSpinBox()
        self.depthSpin.setRange(0, 5)
        self.depthSpin.setValue(0)
        self.depthSpin.setPrefix("Depth: ")
        self.filterCombo = QtWidgets.QComboBox()
        self.filterCombo.addItems(["Show: All", "Show: Broken", "Show: Redirects", "Show: Good", "Show: Skipped"])
        self.startBtn = OpsButton("Start Scan")
        self.stopBtn = OpsButton("Stop")
        self.stopBtn.setChecked(False)
        self.stopBtn.setEnabled(False)

        for b in (self.startBtn, self.stopBtn):
            b.setChecked(False)

        row.addWidget(self.urlEdit, 1)
        row.addWidget(self.depthSpin)
        row.addWidget(self.filterCombo)
        row.addWidget(self.startBtn)
        row.addWidget(self.stopBtn)
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

        self.view = QtWidgets.QTextEdit()
        self.view.setReadOnly(True)
        self.view.setStyleSheet("background:#1B222C; color:#E8EDF5; border:1px solid #2E3B4A;")
        v.addWidget(self.view, 1)

        self.startBtn.clicked.connect(self._start_scan)
        self.stopBtn.clicked.connect(self._stop_scan)
        self.filterCombo.currentIndexChanged.connect(self._refresh_view)

    def _start_scan(self):
        start_url = self.urlEdit.text().strip()
        if not start_url:
            QtWidgets.QMessageBox.critical(self, "Link Verifier", "Please enter a URL.")
            return
        if not start_url.startswith("http"):
            start_url = "http://" + start_url
            self.urlEdit.setText(start_url)

        depth = int(self.depthSpin.value())
        self.view.clear()
        self.results = []
        self._stop = False
        self.stopBtn.setEnabled(True)
        self._setBusy("Scanning...")

        def run():
            try:
                report_lines = []
                visited = set()
                self._add_log_line("Starting at: " + start_url)
                self._crawl(start_url, depth, visited)
                self._add_log_line("")
                self._add_log_line("Scan complete. Writing report.txt ...")
                self._write_report()
            except Exception as e:
                self._add_log_line("Error: " + str(e))
            finally:
                QtCore.QMetaObject.invokeMethod(self, "_finish", QtCore.Qt.QueuedConnection)

        threading.Thread(target=run, daemon=True).start()

    def _stop_scan(self):
        self._stop = True
        self._add_log_line("Stop requested...")

    def _setBusy(self, msg):
        self.statusLbl.setText(msg)
        self.progress.show()

    @QtCore.Slot()
    def _finish(self):
        self.progress.hide()
        self.statusLbl.setText("Done")
        self.stopBtn.setEnabled(False)
        self._refresh_view()

    def _add_log_line(self, text):
        QtCore.QMetaObject.invokeMethod(self.view, "append", QtCore.Qt.QueuedConnection, QtCore.Q_ARG(str, text))

    def _fetch_links(self, url):
        try:
            r = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code >= 400:
                return [], r.status_code
            soup = BeautifulSoup(r.text, "html.parser")
            links = []
            for a in soup.find_all("a", href=True):
                links.append(urljoin(url, a["href"]))
            return links, r.status_code
        except Exception:
            return [], None

    def _check_link(self, url):
        try:
            r = requests.head(url, allow_redirects=True, timeout=8, headers={"User-Agent": "Mozilla/5.0"})
            code = r.status_code
            final_url = r.url
            redirected = len(r.history) > 0
            if code >= 400 or code == 0:
                r = requests.get(url, stream=True, allow_redirects=True, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
                code = r.status_code
                final_url = r.url
                redirected = len(r.history) > 0
            return code, final_url, redirected
        except Exception:
            return None, None, False

    def _add_result(self, url, code, final_url, redirected):
        if code is None:
            category = "broken"
        elif code >= 400:
            category = "broken"
        elif 300 <= code <= 399 or redirected:
            category = "redirect"
        elif 200 <= code <= 299:
            category = "good"
        else:
            category = "skipped"

        entry = {"url": url, "code": code, "category": category, "final_url": final_url or ""}
        self.results.append(entry)

        # incremental append for current filter
        if self._should_show(entry):
            QtCore.QMetaObject.invokeMethod(
                self.view, "append", QtCore.Qt.QueuedConnection, QtCore.Q_ARG(str, self._format_entry(entry))
            )

    def _should_show(self, entry):
        idx = self.filterCombo.currentIndex()
        if idx == 0:
            return True
        if idx == 1:
            return entry["category"] == "broken"
        if idx == 2:
            return entry["category"] == "redirect"
        if idx == 3:
            return entry["category"] == "good"
        if idx == 4:
            return entry["category"] == "skipped"
        return True

    def _format_entry(self, e):
        # color-coded HTML lines; ASCII only
        cat = e["category"]
        code = "None" if e["code"] is None else str(e["code"])
        url = e["url"]
        final_url = e["final_url"]
        if cat == "broken":
            color = "#F27878"
        elif cat == "redirect":
            color = "#E8B45D"
        elif cat == "good":
            color = "#7FD3A2"
        else:
            color = "#B8C3D1"
        if cat == "redirect" and final_url and final_url != url:
            tail = " -> " + final_url
        else:
            tail = ""
        return "<span style='color:" + color + "'>" + code + "</span> " + url + tail

    def _refresh_view(self):
        # rebuild display from self.results using current filter
        lines = []
        for e in self.results:
            if self._should_show(e):
                lines.append(self._format_entry(e))
        html = "\n".join(lines) if lines else "<span style='color:#B8C3D1'>No results for this filter.</span>"
        self.view.setHtml(html)

    def _crawl(self, start_url, max_depth, visited):
        origin = urlparse(start_url)
        base_host = origin.netloc.lower()

        def crawl_one(url, depth):
            if self._stop:
                return
            if url in visited:
                self._add_log_line("SKIP " + url)
                self.results.append({"url": url, "code": None, "category": "skipped", "final_url": ""})
                return
            visited.add(url)
            code, final_url, redirected = self._check_link(url)
            self._add_result(url, code, final_url, redirected)

            if depth >= max_depth:
                return

            links, _status = self._fetch_links(url)
            for link in links:
                if self._stop:
                    return
                pr = urlparse(link)
                if pr.scheme in ("http", "https") and pr.netloc.lower() == base_host:
                    crawl_one(link, depth + 1)

        crawl_one(start_url, 0)

    def _write_report(self):
        # Group in the required order: Broken, Redirects, Good, Skipped
        broken = [e for e in self.results if e["category"] == "broken"]
        redirects = [e for e in self.results if e["category"] == "redirect"]
        good = [e for e in self.results if e["category"] == "good"]
        skipped = [e for e in self.results if e["category"] == "skipped"]

        try:
            with open("report.txt", "w") as f:
                f.write("[BROKEN LINKS]\n")
                for e in broken:
                    code = "None" if e["code"] is None else str(e["code"])
                    f.write(code + " " + e["url"] + "\n")

                f.write("\n[REDIRECTED LINKS]\n")
                for e in redirects:
                    code = "None" if e["code"] is None else str(e["code"])
                    if e["final_url"] and e["final_url"] != e["url"]:
                        f.write(code + " " + e["url"] + " -> " + e["final_url"] + "\n")
                    else:
                        f.write(code + " " + e["url"] + "\n")

                f.write("\n[GOOD LINKS]\n")
                for e in good:
                    code = "None" if e["code"] is None else str(e["code"])
                    f.write(code + " " + e["url"] + "\n")

                f.write("\n[SKIPPED]\n")
                for e in skipped:
                    f.write("SKIP " + e["url"] + "\n")

            self._add_log_line("Saved report.txt")
        except Exception as fe:
            self._add_log_line("Could not write report.txt: " + str(fe))


# ------------------------------
# Entry Point
# ------------------------------
def main():
    app = QtWidgets.QApplication(sys.argv)
    app.setFont(QtGui.QFont("Arial", 10))

    # Prompted auto-update with backup
    check_for_updates_gui(None)

    w = OpsWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
