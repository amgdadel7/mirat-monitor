#!/usr/bin/env python3
"""Authorized, non-destructive website and source-tree audit dashboard (stdlib only)."""
from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
import sqlite3
import secrets
import hashlib
from urllib.parse import quote
from collections import deque
from datetime import datetime, timezone
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse, urldefrag, parse_qs
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
MAX_JOBS = 24
JOBS: dict[str, dict] = {}
JOBS_LOCK = threading.Lock()
IGNORED_DIRS = {".git", "node_modules", "vendor", "venv", ".venv", "__pycache__", ".next", "dist", "build", "coverage", ".idea", ".vscode"}
TEXT_EXTS = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".php", ".rb", ".go", ".rs", ".cs", ".cpp", ".c", ".h", ".hpp", ".swift", ".kt", ".kts", ".html", ".htm", ".css", ".scss", ".vue", ".svelte", ".json", ".yml", ".yaml", ".toml", ".ini", ".xml", ".sql", ".sh", ".env.example", ".md", ".txt", ".conf", ".properties"}


def finding(severity, title, description, location, recommendation, category="عام"):
    return {"severity": severity, "title": title, "description": description,
            "location": location, "recommendation": recommendation, "category": category}


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.images = [], []
        self.title = ""
        self.in_title = False
        self.description = ""
        self.viewport = False
        self.forms = []
        self.form = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "title":
            self.in_title = True
        elif tag == "meta":
            name = (a.get("name") or "").lower()
            if name == "description": self.description = a.get("content", "").strip()
            if name == "viewport": self.viewport = True
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"].strip())
        elif tag == "img":
            self.images.append(a)
        elif tag == "form":
            self.form = {"method": (a.get("method") or "get").lower(), "inputs": [], "labels": 0}
            self.forms.append(self.form)
        elif tag == "label" and self.form is not None:
            self.form["labels"] += 1
        elif tag in ("input", "textarea", "select") and self.form is not None:
            typ = (a.get("type") or "text").lower()
            if typ not in ("hidden", "submit", "button", "reset", "image"):
                self.form["inputs"].append(a)

    def handle_endtag(self, tag):
        if tag == "title": self.in_title = False
        elif tag == "form": self.form = None

    def handle_data(self, data):
        if self.in_title: self.title += data.strip()


def scan_url(target, progress):
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("أدخل رابطاً كاملاً يبدأ بـ http:// أو https://")
    origin = f"{parsed.scheme}://{parsed.netloc}"
    # Preserve an explicitly supplied route/query; only add a slash for a bare host.
    root_url = target if parsed.path or parsed.query else origin + "/"
    queue = deque([root_url])
    queued = {root_url}
    visited, findings, pages = set(), [], []
    max_pages = 20
    headers_seen = None
    while queue and len(visited) < max_pages:
        current = queue.popleft()
        if current in visited: continue
        visited.add(current)
        progress(f"جارٍ فحص الصفحة {len(visited)} من {max_pages}")
        request = Request(current, headers={"User-Agent": "AmanAudit/1.0 (authorized non-destructive audit)", "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"})
        try:
            with urlopen(request, timeout=8) as response:
                status = response.status
                response_headers = response.headers
                content_type = response_headers.get("Content-Type", "")
                body = response.read(1_500_000)
                final_url = response.geturl()
        except HTTPError as exc:
            status, response_headers, content_type, body, final_url = exc.code, exc.headers, "", b"", current
        except Exception as exc:
            findings.append(finding("high", "تعذّر الوصول إلى الرابط", f"تعذر جلب الصفحة: {str(exc)[:180]}", current, "تحقق من صحة الرابط، وإمكانية الوصول، وإعدادات DNS أو الشهادة.", "التوفر"))
            pages.append({"url": current, "status": "تعذّر الاتصال"})
            continue
        pages.append({"url": final_url, "status": status})
        if headers_seen is None: headers_seen = response_headers
        if status >= 500:
            findings.append(finding("high", f"استجابة خادم {status}", "أعاد الخادم خطأ من فئة 5xx عند طلب هذه الصفحة.", final_url, "راجع سجلات التطبيق والخادم، وأصلح الاستثناء أو الاعتماد المتعطل.", "التوفر"))
        elif status >= 400:
            findings.append(finding("medium", f"صفحة غير متاحة ({status})", "أعاد الرابط استجابة 4xx.", final_url, "صحح الرابط أو أضف صفحة مناسبة، وحدّث الروابط الداخلية التي تشير إليه.", "الروابط"))
        if "html" not in content_type.lower() or not body: continue
        parser = PageParser()
        try: parser.feed(body.decode("utf-8", errors="replace"))
        except Exception: pass
        if not parser.title.strip():
            findings.append(finding("low", "الصفحة بلا عنوان واضح", "لم يُعثر على نص داخل وسم <title>.", final_url, "أضف عنواناً فريداً وموجزاً يصف الصفحة.", "إمكانية الوصول وSEO"))
        if not parser.viewport:
            findings.append(finding("low", "إعداد العرض المتجاوب مفقود", "لم يُعثر على وسم viewport في الصفحة.", final_url, "أضف وسم viewport مناسباً لتحسين العرض على الهواتف.", "التوافق"))
        missing_alt = sum(1 for image in parser.images if "alt" not in image)
        if missing_alt:
            findings.append(finding("medium", f"صور بلا نص بديل ({missing_alt})", "قد لا تكون بعض الصور مفهومة لمستخدمي قارئات الشاشة.", final_url, "أضف alt وصفياً للصور المهمة، واستخدم alt=\"\" للصور الزخرفية.", "إمكانية الوصول"))
        for form in parser.forms:
            if form["inputs"] and form["labels"] < len(form["inputs"]):
                findings.append(finding("low", "حقول نموذج قد تفتقر إلى تسميات", f"النموذج يحتوي {len(form['inputs'])} حقلاً و{form['labels']} تسمية label.", final_url, "اربط كل حقل بتسمية label باستخدام for/id أو aria-label.", "إمكانية الوصول"))
        if not parser.description:
            findings.append(finding("info", "وصف الصفحة غير موجود", "لم يُعثر على meta description؛ هذا تنبيه تحسين وليس عطلاً وظيفياً.", final_url, "أضف وصفاً مختصراً إذا كانت الصفحة تحتاج إلى ظهور أفضل في نتائج البحث.", "إمكانية الوصول وSEO"))
        for href in parser.links:
            if href.startswith(("#", "mailto:", "tel:", "javascript:", "data:")): continue
            absolute = urldefrag(urljoin(final_url, href))[0]
            p = urlparse(absolute)
            if p.scheme in ("http", "https") and p.netloc == parsed.netloc and absolute not in queued and len(queued) < max_pages * 3:
                queued.add(absolute)
                queue.append(absolute)
    if not pages:
        findings.append(finding("high", "لم تُفحص أي صفحة", "لم يتمكن الفاحص من تحميل صفحات الموقع.", target, "تحقق من الرابط ومن أن النظام متاح من بيئة الفحص.", "التوفر"))
    if headers_seen:
        checks = [
            ("Content-Security-Policy", "سياسة أمان المحتوى CSP غير موجودة", "أضف CSP ملائمة، وابدأ بوضع التقرير قبل فرضها لتجنب تعطيل موارد الموقع.", "medium"),
            ("X-Content-Type-Options", "حماية MIME sniffing غير مضبوطة", "أرسل X-Content-Type-Options: nosniff.", "low"),
            ("Referrer-Policy", "سياسة الإحالة غير محددة", "اضبط Referrer-Policy بقيمة تقلل تسرب معلومات URL، مثل strict-origin-when-cross-origin.", "low"),
            ("X-Frame-Options", "حماية التأطير غير ظاهرة", "استخدم CSP frame-ancestors؛ ويمكن دعمها بـ X-Frame-Options للتوافق.", "low"),
        ]
        for header, title, remedy, severity in checks:
            if not headers_seen.get(header):
                findings.append(finding(severity, title, f"لم يُعثر على ترويسة {header} في استجابة الصفحة الأولى.", root_url, remedy, "أمان الويب"))
        if parsed.scheme == "https" and not headers_seen.get("Strict-Transport-Security"):
            findings.append(finding("low", "HSTS غير مفعّل", "لا تظهر ترويسة Strict-Transport-Security على الاستجابة الأولى.", root_url, "بعد التأكد من عمل HTTPS على جميع النطاقات الفرعية، اضبط HSTS بمدة مناسبة.", "أمان الويب"))
    if parsed.scheme == "http":
        findings.append(finding("high", "الموقع يستخدم HTTP غير المشفر", "الرابط المستهدف لا يستخدم HTTPS، مما يعرّض البيانات للاعتراض أو التعديل أثناء النقل.", target, "فعّل شهادة TLS وأعد توجيه HTTP إلى HTTPS.", "أمان الويب"))
    if len(visited) >= max_pages and queue:
        findings.append(finding("info", f"تم بلوغ حد الصفحات ({max_pages})", "توقف الفحص عند الحد الوقائي؛ قد تبقى مسارات أخرى غير مفحوصة.", target, "قسّم الموقع إلى أقسام أو ارفع الحد بعد مراجعة الأداء.", "حدود الفحص"))
    return {"pages_scanned": len(pages), "pages": pages, "findings": findings,
            "notes": ["الفحص يطلب الصفحات فقط؛ لا يرسل النماذج ولا ينفذ عمليات كتابة أو تسجيل دخول.", "الزحف محدود بـ 20 صفحة ضمن نفس المضيف. لا يشمل اختبار اختراق أو تدقيق المصادقة أو منطق الأعمال."]}


RULES = [
    ("secret", re.compile(r'''(?i)(?:api[_-]?key|client[_-]?secret|password|passwd|access[_-]?token|secret[_-]?key)\s*[:=]\s*["'][^"'\s]{8,}["']'''), "احتمال سر أو مفتاح مضمّن", "قد يحتوي السطر على قيمة سرية مكتوبة مباشرة في الشيفرة.", "انقل السر إلى مدير أسرار أو متغير بيئة، وأبطل القيمة المكشوفة ودوّرها. قيمة السر مخفية في التقرير.", "أمان", "high"),
    ("eval", re.compile(r"\b(?:eval|exec)\s*\("), "استخدام eval/exec", "تنفيذ نص ديناميكي قد يتيح تنفيذ شيفرة غير موثوقة.", "تجنب التنفيذ الديناميكي؛ استخدم محللاً أو واجهة آمنة مع تحقق صارم من المدخلات.", "أمان", "high"),
    ("shell", re.compile(r"\bshell\s*=\s*True\b"), "تشغيل أمر بقشرة النظام", "shell=True مع مدخلات غير موثوقة قد يسبب حقن أوامر.", "استخدم subprocess بقائمة وسائط دون shell، وتحقق من المدخلات.", "أمان", "high"),
    ("tls", re.compile(r"(?i)(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=?\s*['\"]?0)"), "تعطيل التحقق من شهادة TLS", "قد يسمح بقبول اتصالات غير موثوقة أو معترضة.", "أعد التحقق من الشهادة، وعالج مشكلة سلسلة الشهادات بدلاً من تعطيل التحقق.", "أمان", "high"),
    ("debug", re.compile(r"(?i)(?:debug\s*[:=]\s*(?:True|true)|APP_DEBUG\s*=\s*true)"), "وضع التصحيح مفعّل", "قد يكشف وضع التصحيح تفاصيل داخلية إذا استُخدم في الإنتاج.", "اجعل وضع التصحيح معطلاً في الإنتاج واضبطه عبر إعدادات بيئة محمية.", "إعدادات", "medium"),
    ("cors", re.compile(r"(?i)(?:Access-Control-Allow-Origin.{0,20}\*|cors\s*\(\s*\))"), "إعداد CORS واسع محتمل", "تم العثور على نمط قد يسمح بطلبات عابرة للنطاقات على نطاق واسع.", "اسمح فقط بالأصول المطلوبة؛ تحقق من الإعداد الفعلي لأن هذا النمط قد يكون مقصوداً أو غير فعّال.", "أمان", "medium"),
    ("http", re.compile(r"(?i)(?:https?://)(?!localhost|127\.0\.0\.1|example\.com)[a-z0-9.-]+"), "رابط HTTP غير مشفر محتمل", "قد يشير النص إلى اعتماد خارجي غير مشفر؛ قد يكون الرابط مثالاً أو غير حساس.", "استخدم HTTPS للاعتمادات الحقيقية، وراجع السطر للتأكد من سياقه.", "أمان", "low"),
    ("innerhtml", re.compile(r"(?i)(?:\.innerHTML\s*=|v-html\s*=)"), "إدراج HTML ديناميكي محتمل", "إدراج محتوى غير موثوق في HTML قد يسبب XSS.", "نقّ المحتوى أو استخدم textContent/قوالب آمنة؛ تحقق من مصدر البيانات قبل الحكم.", "أمان", "medium"),
    ("sql", re.compile(r"(?i)(?:execute|executemany|query)\s*\([^\n]*(?:\+\s*\w|%\s*\(|\.format\s*\(|f[\"'])"), "استعلام قاعدة بيانات مركّب ديناميكياً", "قد يكون الاستعلام معرضاً لحقن SQL إذا دمج مدخلات المستخدم مباشرة.", "استخدم الاستعلامات ذات المعاملات (parameterized queries)، وراجع مصدر القيم.", "أمان", "medium"),
    ("todo", re.compile(r"(?i)\b(?:TODO|FIXME|XXX|HACK)\b"), "ملاحظة TODO/FIXME", "وُجدت ملاحظة عمل معلّقة في الملف.", "تحقق مما إذا كانت الملاحظة تمثل عملاً غير مكتمل أو عيباً فعلياً.", "جودة الشيفرة", "info"),
]


def safe_display_line(line, rule_id):
    line = line.strip()
    if rule_id == "secret":
        line = re.sub(r'''(?i)((?:api[_-]?key|client[_-]?secret|password|passwd|access[_-]?token|secret[_-]?key)\s*[:=]\s*["'])[^"']+(["'])''', r"\1[محجوب]\2", line)
    return line[:200]


def scan_path(target, progress):
    raw = Path(target).expanduser()
    path = raw.resolve(strict=True)
    allowed = Path.home().resolve()
    if path != allowed and allowed not in path.parents:
        raise ValueError("لأسباب أمان، يقتصر فحص المسارات المحلية في هذه النسخة على الملفات داخل مجلد العمل /home/user.")
    findings, files, deps = [], [], []
    if path.is_file(): candidates = [path]
    elif path.is_dir():
        candidates = []
        for root, dirs, names in os.walk(path):
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS and not d.startswith(".")]
            for name in names:
                p = Path(root) / name
                if p.suffix.lower() in TEXT_EXTS or name in {"Dockerfile", "Makefile", ".env", ".env.local", "Gemfile", "Procfile"}:
                    candidates.append(p)
                if len(candidates) >= 2000: break
            if len(candidates) >= 2000: break
    else: raise ValueError("المسار المحدد ليس ملفاً أو مجلداً.")
    total_bytes = 0
    syntax_checked = 0
    for index, file in enumerate(candidates, start=1):
        try:
            size = file.stat().st_size
            if size > 1_000_000 or total_bytes + size > 50_000_000: continue
            content = file.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeError): continue
        total_bytes += size
        rel = str(file.relative_to(path if path.is_dir() else path.parent))
        files.append(rel)
        progress(f"جارٍ تحليل الملفات {index} من {len(candidates)}")
        for line_num, line in enumerate(content.splitlines(), start=1):
            for rule_id, pattern, title, desc, remedy, category, severity in RULES:
                if pattern.search(line):
                    findings.append(finding(severity, title, desc, f"{rel}:{line_num}", remedy + (" السطر: " + safe_display_line(line, rule_id) if rule_id != "secret" else ""), category))
                    break
        if file.suffix == ".py" and syntax_checked < 40:
            syntax_checked += 1
            try: ast.parse(content, filename=rel)
            except SyntaxError as exc:
                findings.append(finding("high", "خطأ صياغة Python", f"تعذر تحليل الشيفرة: {exc.msg}.", f"{rel}:{exc.lineno or 1}", "صحح صياغة الملف ثم أعد الفحص.", "الصياغة"))
        elif file.suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"} and shutil.which("node") and syntax_checked < 40:
            syntax_checked += 1
            if file.suffix not in {".jsx", ".ts", ".tsx"}:
                try:
                    result = subprocess.run(["node", "--check", str(file)], capture_output=True, text=True, timeout=5, cwd=str(path if path.is_dir() else path.parent))
                    if result.returncode:
                        findings.append(finding("high", "خطأ صياغة JavaScript", (result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "فشل فحص الصياغة.")[:240], rel, "صحح الخطأ الذي أشار إليه محلل Node.js.", "الصياغة"))
                except (subprocess.TimeoutExpired, OSError): pass
        name = file.name.lower()
        if name in {"package.json", "composer.json", "pyproject.toml", "requirements.txt", "pom.xml", "gemfile", "go.mod", "cargo.toml"}:
            deps.append(rel)
    if len(candidates) >= 2000:
        findings.append(finding("info", "توقف تعداد الملفات عند الحد الوقائي", "تمت معالجة أول 2000 ملف مرشح كحد أقصى.", str(path), "قسّم المشروع أو استبعد المجلدات الكبيرة غير اللازمة.", "حدود الفحص"))
    if deps:
        findings.append(finding("info", f"تم العثور على ملفات اعتماد ({len(deps)})", "تم رصد ملفات تعريف اعتماد، لكن لم يُجرَ استعلام عن قواعد بيانات الثغرات أو تثبيت للحزم.", ", ".join(deps[:10]), "شغّل أداة تدقيق الاعتمادات المناسبة للمنظومة (مثل npm audit أو pip-audit) ضمن بيئة المشروع وبعد مراجعة الأثر.", "الاعتمادات"))
    if not findings:
        findings.append(finding("info", "لم تُكتشف أنماط من القواعد المحدودة", "هذه النتيجة لا تثبت خلو النظام من الأخطاء؛ الفاحص الساكن لا يفهم كل سياقات اللغات.", str(path), "شغّل اختبارات المشروع وأدوات التحليل المتخصصة ومراجعة بشرية.", "حدود الفحص"))
    return {"pages_scanned": 0, "files_scanned": len(files), "files": files[:300], "findings": findings,
            "notes": ["تحليل ساكن غير تنفيذي: لم نشغّل التطبيق أو اختبارات المشروع، ولم نغيّر الملفات.", "القواعد مبنية على أنماط عامة وقد تنتج نتائج إيجابية كاذبة أو تفوّت أخطاء سياقية.", "لا يتضمن فحصاً شاملاً للتبعيات أو قواعد بيانات CVE أو منطق العمل أو إعدادات النشر خارج الملفات المقروءة."]}


def summarize(findings):
    counts = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
    for item in findings: counts[item["severity"]] = counts.get(item["severity"], 0) + 1
    weighted = counts["critical"] * 18 + counts["high"] * 10 + counts["medium"] * 5 + counts["low"] * 2
    score = max(0, min(100, 100 - weighted))
    return {"counts": counts, "score": score}


def run_job(job_id, kind, target):
    with JOBS_LOCK: JOBS[job_id]["state"] = "running"
    try:
        progress = lambda text: update_job(job_id, progress=text)
        result = scan_url(target, progress) if kind == "url" else scan_path(target, progress)
        result["summary"] = summarize(result["findings"])
        result["target"] = target
        result["kind"] = kind
        result["finished_at"] = datetime.now(timezone.utc).isoformat()
        update_job(job_id, state="done", result=result, progress="اكتمل الفحص")
    except Exception as exc:
        update_job(job_id, state="error", error=str(exc), progress="تعذر إكمال الفحص")


def update_job(job_id, **kwargs):
    with JOBS_LOCK:
        if job_id in JOBS: JOBS[job_id].update(kwargs)


DB_PATH = Path(os.environ.get("DB_PATH", ROOT / "mirat.sqlite3"))


def db_connect():
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


def init_database():
    with db_connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, platform TEXT NOT NULL,
            api_key TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS issues (
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            fingerprint TEXT NOT NULL, title TEXT NOT NULL, culprit TEXT NOT NULL DEFAULT '',
            level TEXT NOT NULL DEFAULT 'error', count INTEGER NOT NULL DEFAULT 1,
            first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'unresolved',
            PRIMARY KEY(project_id, fingerprint)
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            fingerprint TEXT NOT NULL, message TEXT NOT NULL, event_type TEXT NOT NULL,
            level TEXT NOT NULL, culprit TEXT NOT NULL DEFAULT '', url TEXT NOT NULL DEFAULT '',
            environment TEXT NOT NULL DEFAULT '', release TEXT NOT NULL DEFAULT '',
            stacktrace TEXT NOT NULL DEFAULT '', timestamp TEXT NOT NULL,
            user_json TEXT NOT NULL DEFAULT '{}', tags_json TEXT NOT NULL DEFAULT '{}',
            extra_json TEXT NOT NULL DEFAULT '{}', received_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS events_by_issue ON events(project_id, fingerprint, id DESC);
        CREATE INDEX IF NOT EXISTS issues_by_project_status ON issues(project_id, status, last_seen DESC);
        """)


def api_origin(handler):
    configured = os.environ.get("PUBLIC_URL", "").strip().rstrip("/")
    if configured: return configured
    scheme = handler.headers.get("X-Forwarded-Proto", "http").split(",")[0].strip()
    if scheme not in ("http", "https"): scheme = "http"
    host = handler.headers.get("Host", "localhost:8000")
    return f"{scheme}://{host}"


def normalized_fingerprint(event):
    explicit = event.get("fingerprint")
    if isinstance(explicit, str) and explicit.strip():
        return hashlib.sha256(explicit.strip().encode("utf-8", "replace")).hexdigest()[:32]
    event_type = str(event.get("type") or event.get("exception_type") or "Error")[:120]
    message = str(event.get("message") or event.get("error") or "Unknown error")[:500]
    message = re.sub(r"\b[0-9a-fA-F]{8,}\b", "<id>", message)
    message = re.sub(r"\b\d+\b", "<n>", message)
    culprit = str(event.get("culprit") or "")
    # Group on the stable error class/message; source location is retained as context.
    basis = f"{event_type.lower()}:{message.lower()}"
    return hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:32]


def load_browser_sdk():
    return r'''(function(){
  var s=document.currentScript,dsn=s&&s.dataset&&s.dataset.dsn,env=(s&&s.dataset&&s.dataset.environment)||"production",release=(s&&s.dataset&&s.dataset.release)||"";
  if(!dsn)return;
  function send(type,message,stack,culprit){
    var event={type:String(type||"Error").slice(0,120),message:String(message||"Unknown error").slice(0,1000),stacktrace:String(stack||"").slice(0,12000),culprit:String(culprit||location.pathname).slice(0,500),url:location.href.slice(0,1500),environment:env,release:release,timestamp:new Date().toISOString(),level:"error"};
    try{var body=new Blob([JSON.stringify(event)],{type:"text/plain;charset=UTF-8"});if(navigator.sendBeacon){navigator.sendBeacon(dsn,body)}else{fetch(dsn,{method:"POST",mode:"cors",keepalive:true,headers:{"Content-Type":"text/plain"},body:JSON.stringify(event)}).catch(function(){})}}catch(_e){}
  }
  window.addEventListener("error",function(e){var x=e.error;send(x&&x.name||"Error",e.message||String(x||"Script error"),x&&x.stack||"",e.filename?e.filename+":"+e.lineno+":"+e.colno:location.pathname)});
  window.addEventListener("unhandledrejection",function(e){var x=e.reason;send(x&&x.name||"UnhandledRejection",x&&x.message||String(x),x&&x.stack||"",location.pathname)});
})();'''


def safe_json_object(value, limit=12000):
    if not isinstance(value, dict): return "{}"
    try: return json.dumps(value, ensure_ascii=False)[:limit]
    except (TypeError, ValueError): return "{}"


init_database()


class Handler(BaseHTTPRequestHandler):
    server_version = "AmanAudit/1.0"
    def log_message(self, fmt, *args): pass

    def send_json(self, data, status=200, cors=False):
        payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        if cors:
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self):
        if self.path.startswith("/api/events/"):
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Access-Control-Max-Age", "600")
            self.end_headers()
        else: self.send_error(404)

    def do_GET(self):
        route = urlparse(self.path)
        if route.path.startswith("/api/status/"):
            job_id = route.path.rsplit("/", 1)[-1]
            with JOBS_LOCK: job = JOBS.get(job_id)
            if not job: return self.send_json({"error": "لم يتم العثور على الفحص"}, 404)
            return self.send_json(job)
        if route.path == "/api/projects":
            with db_connect() as db:
                rows = db.execute("""SELECT p.id,p.name,p.platform,p.created_at,
                  (SELECT COUNT(*) FROM issues i WHERE i.project_id=p.id AND i.status='unresolved') AS open_issues,
                  (SELECT COUNT(*) FROM issues i WHERE i.project_id=p.id AND i.status='resolved') AS resolved_issues,
                  (SELECT COALESCE(SUM(i.count),0) FROM issues i WHERE i.project_id=p.id) AS events
                  FROM projects p ORDER BY p.created_at DESC""").fetchall()
            return self.send_json({"projects": [dict(r) for r in rows]})
        if route.path.startswith("/api/projects/"):
            project_id = route.path.rsplit("/", 1)[-1]
            with db_connect() as db: row = db.execute("SELECT id,name,platform,api_key,created_at FROM projects WHERE id=?", (project_id,)).fetchone()
            if not row: return self.send_json({"error": "المشروع غير موجود"}, 404)
            return self.send_json(dict(row) | {"dsn": api_origin(self) + "/api/events/" + row["api_key"]})
        if route.path == "/api/issues":
            query = parse_qs(route.query)
            project_id = query.get("project_id", [""])[0]
            status = query.get("status", ["unresolved"])[0]
            if status not in ("unresolved", "resolved", "all"): status = "unresolved"
            with db_connect() as db:
                if status == "all":
                    rows = db.execute("SELECT * FROM issues WHERE project_id=? ORDER BY last_seen DESC LIMIT 300", (project_id,)).fetchall()
                else:
                    rows = db.execute("SELECT * FROM issues WHERE project_id=? AND status=? ORDER BY last_seen DESC LIMIT 300", (project_id, status)).fetchall()
            return self.send_json({"issues": [dict(r) for r in rows]})
        if route.path == "/api/issue-events":
            query = parse_qs(route.query)
            project_id, fingerprint = query.get("project_id", [""])[0], query.get("fingerprint", [""])[0]
            with db_connect() as db:
                rows = db.execute("SELECT id,message,event_type,level,culprit,url,environment,release,stacktrace,timestamp,user_json,tags_json,extra_json FROM events WHERE project_id=? AND fingerprint=? ORDER BY id DESC LIMIT 30", (project_id, fingerprint)).fetchall()
            events = []
            for row in rows:
                item = dict(row)
                for col in ("user_json", "tags_json", "extra_json"):
                    try: item[col.removesuffix("_json")] = json.loads(item.pop(col))
                    except (ValueError, TypeError): item.pop(col, None)
                events.append(item)
            return self.send_json({"events": events})
        if route.path == "/sdk.js":
            body = load_browser_sdk().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "public, max-age=300")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers(); self.wfile.write(body)
            return
        if route.path in ("/", "/index.html", "/scanner", "/scanner.html"):
            filename = "scanner.html" if route.path.startswith("/scanner") else "index.html"
            try: data = (ROOT / filename).read_bytes()
            except OSError: return self.send_error(404)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if route.path in ("/mirat_sdk.py", "/mirat-node.js", "/README.md"):
            filename = route.path.lstrip("/")
            try: data = (ROOT / filename).read_bytes()
            except OSError: return self.send_error(404)
            content_type = "text/plain; charset=utf-8" if filename.endswith((".py", ".js", ".md")) else "application/octet-stream"
            self.send_response(200); self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
            return
        self.send_error(404)

    def read_json_body(self, maximum):
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > maximum: raise ValueError("حجم الطلب غير صالح أو يتجاوز الحد المسموح")
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def do_POST(self):
        route = urlparse(self.path)
        try:
            if route.path == "/api/projects":
                body = self.read_json_body(10000)
                name = str(body.get("name", "")).strip()[:80]
                platform = str(body.get("platform", "javascript"))
                if not name: return self.send_json({"error": "اكتب اسماً للمشروع"}, 400)
                if platform not in ("javascript", "node", "python", "generic"): platform = "generic"
                project_id, key = uuid.uuid4().hex[:12], secrets.token_urlsafe(24)
                created = datetime.now(timezone.utc).isoformat()
                with db_connect() as db:
                    db.execute("INSERT INTO projects(id,name,platform,api_key,created_at) VALUES(?,?,?,?,?)", (project_id,name,platform,key,created))
                return self.send_json({"id": project_id,"name":name,"platform":platform,"api_key":key,"dsn":api_origin(self)+"/api/events/"+key,"created_at":created}, 201)

            if route.path.startswith("/api/events/"):
                key = route.path.rsplit("/", 1)[-1]
                raw = self.rfile.read(min(int(self.headers.get("Content-Length", "0")), 262145))
                if not raw or len(raw) > 262144: return self.send_json({"error":"حجم الحدث غير صالح"}, 413, cors=True)
                try: event = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError): return self.send_json({"error":"صيغة الحدث غير صالحة"}, 400, cors=True)
                if not isinstance(event, dict): return self.send_json({"error":"صيغة الحدث يجب أن تكون كائناً JSON"}, 400, cors=True)
                with db_connect() as db:
                    project = db.execute("SELECT id FROM projects WHERE api_key=?", (key,)).fetchone()
                    if not project: return self.send_json({"error":"مفتاح المشروع غير صحيح"}, 404, cors=True)
                    project_id = project["id"]
                    event_type = str(event.get("type") or event.get("exception_type") or "Error")[:120]
                    message = str(event.get("message") or event.get("error") or "Unknown error")[:1000]
                    culprit = str(event.get("culprit") or "")[:500]
                    level = str(event.get("level") or "error").lower()
                    if level not in ("fatal", "error", "warning", "info"): level = "error"
                    url = str(event.get("url") or "")[:1500]
                    environment = str(event.get("environment") or "")[:80]
                    release = str(event.get("release") or "")[:120]
                    stacktrace = str(event.get("stacktrace") or event.get("stack") or "")[:12000]
                    timestamp = str(event.get("timestamp") or datetime.now(timezone.utc).isoformat())[:80]
                    fingerprint = normalized_fingerprint(event)
                    title = (event_type + ": " + message)[:300]
                    received = datetime.now(timezone.utc).isoformat()
                    db.execute("INSERT INTO events(project_id,fingerprint,message,event_type,level,culprit,url,environment,release,stacktrace,timestamp,user_json,tags_json,extra_json,received_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (project_id,fingerprint,message,event_type,level,culprit,url,environment,release,stacktrace,timestamp,safe_json_object(event.get("user")),safe_json_object(event.get("tags")),safe_json_object(event.get("extra")),received))
                    db.execute("""INSERT INTO issues(project_id,fingerprint,title,culprit,level,count,first_seen,last_seen,status)
                        VALUES(?,?,?,?,?,1,?,?, 'unresolved') ON CONFLICT(project_id,fingerprint) DO UPDATE SET
                        title=excluded.title,culprit=excluded.culprit,level=excluded.level,count=issues.count+1,
                        last_seen=excluded.last_seen,status='unresolved'""",
                        (project_id,fingerprint,title,culprit,level,timestamp,timestamp))
                    db.execute("DELETE FROM events WHERE received_at < datetime('now','-90 days')")
                    db.execute("UPDATE issues SET count=(SELECT COUNT(*) FROM events e WHERE e.project_id=issues.project_id AND e.fingerprint=issues.fingerprint), first_seen=COALESCE((SELECT MIN(e.timestamp) FROM events e WHERE e.project_id=issues.project_id AND e.fingerprint=issues.fingerprint),first_seen), last_seen=COALESCE((SELECT MAX(e.timestamp) FROM events e WHERE e.project_id=issues.project_id AND e.fingerprint=issues.fingerprint),last_seen) WHERE project_id=?", (project_id,))
                    db.execute("DELETE FROM issues WHERE project_id=? AND NOT EXISTS (SELECT 1 FROM events e WHERE e.project_id=issues.project_id AND e.fingerprint=issues.fingerprint)", (project_id,))
                return self.send_json({"accepted":True,"fingerprint":fingerprint}, 202, cors=True)

            if route.path == "/api/issues/status":
                body = self.read_json_body(10000)
                project_id, fingerprint = str(body.get("project_id", "")), str(body.get("fingerprint", ""))
                status = str(body.get("status", ""))
                if status not in ("resolved", "unresolved"): return self.send_json({"error":"حالة غير مدعومة"}, 400)
                with db_connect() as db:
                    cursor = db.execute("UPDATE issues SET status=? WHERE project_id=? AND fingerprint=?", (status, project_id, fingerprint))
                    if cursor.rowcount == 0: return self.send_json({"error":"المشكلة غير موجودة"}, 404)
                return self.send_json({"ok":True,"status":status})

            if route.path != "/api/scan": return self.send_json({"error":"المسار غير موجود"}, 404)
            body = self.read_json_body(10000)
            kind, target = body.get("kind"), str(body.get("target", "")).strip()
            if kind not in ("url", "path") or not target: return self.send_json({"error": "حدد نوع الهدف والمسار أو الرابط"}, 400)
            with JOBS_LOCK:
                if len(JOBS) >= MAX_JOBS:
                    old = next((key for key, val in JOBS.items() if val.get("state") in ("done", "error")), None)
                    if old: JOBS.pop(old, None)
                    else: return self.send_json({"error": "يوجد عدد كبير من الفحوص النشطة؛ حاول لاحقاً"}, 429)
                job_id = uuid.uuid4().hex[:12]
                JOBS[job_id] = {"id": job_id, "state": "queued", "progress": "بانتظار بدء الفحص"}
            threading.Thread(target=run_job, args=(job_id, kind, target), daemon=True).start()
            return self.send_json({"id": job_id}, 202)
        except (ValueError, json.JSONDecodeError) as exc:
            return self.send_json({"error": f"طلب غير صالح: {exc}"}, 400)
        except Exception as exc:
            return self.send_json({"error": f"تعذر إكمال الطلب: {str(exc)[:180]}"}, 500)


def main():
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8500"))
    print(f"Aman Audit listening on http://{host}:{port}")
    ThreadingHTTPServer((host, port), Handler).serve_forever()

if __name__ == "__main__": main()
