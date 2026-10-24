from __future__ import annotations

import html
import os
import re
import sqlite3
import textwrap
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Thread, Lock
from typing import Any
from urllib.parse import urlparse

import feedparser
import requests
from flask import Flask, abort, flash, redirect, render_template, request, send_file, url_for

BASE = Path(__file__).resolve().parent
DB_PATH = BASE / "techintel.db"
DIGEST_DIR = BASE / "digests"
DIGEST_DIR.mkdir(exist_ok=True)
APP_HOST = os.getenv("TECHINTEL_HOST", "127.0.0.1")
APP_PORT = int(os.getenv("TECHINTEL_PORT", "5000"))
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434/api/generate")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")
USER_AGENT = "z4dsu/1.0 (personal news dashboard)"
CONNECT_TIMEOUT = 4
READ_TIMEOUT = 8
MAX_FEED_WORKERS = 10
RETRY_COUNT = 1
refresh_lock = Lock()
app = Flask(__name__)
app.secret_key = os.getenv("TECHINTEL_SECRET", "change-this-local-dev-secret")

FEEDS = {
    "Cybersecurity": [
        ("CISA Advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
        ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
        ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
        ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
        ("SecurityWeek", "https://www.securityweek.com/feed/"),
        ("Dark Reading", "https://www.darkreading.com/rss.xml"),
        ("Schneier on Security", "https://www.schneier.com/feed/atom/"),
        ("Google Project Zero", "https://googleprojectzero.blogspot.com/feeds/posts/default"),
        ("Cisco Talos", "https://blog.talosintelligence.com/rss/"),
        ("Microsoft Security Blog", "https://www.microsoft.com/en-us/security/blog/feed/"),
        ("AWS Security Blog", "https://aws.amazon.com/blogs/security/feed/"),
        ("Malwarebytes Labs", "https://www.malwarebytes.com/blog/feed/index.xml"),
        ("NIST Cybersecurity Insights", "https://www.nist.gov/blogs/cybersecurity-insights/rss.xml"),
        ("CVE Feed", "https://cvefeed.io/rssfeed/latest.xml"),
    ],
    "Technology": [
        ("Ars Technica", "https://feeds.arstechnica.com/arstechnica/index"),
        ("The Register", "https://www.theregister.com/headlines.atom"),
        ("TechCrunch", "https://techcrunch.com/feed/"),
        ("Hacker News Front Page", "https://hnrss.org/frontpage"),
        ("Google AI Blog", "https://blog.research.google/feeds/posts/default"),
        ("OpenAI News", "https://openai.com/news/rss.xml"),
        ("Cloudflare Blog", "https://blog.cloudflare.com/rss/"),
        ("GitHub Blog", "https://github.blog/feed/"),
        ("The Verge", "https://www.theverge.com/rss/index.xml"),
    ],
    "Developer": [
        ("Python Insider", "https://feeds.feedburner.com/PythonInsider"),
        ("Node.js Blog", "https://nodejs.org/en/feed/blog.xml"),
        ("GitHub Changelog", "https://github.blog/changelog/feed/"),
        ("Mozilla Hacks", "https://hacks.mozilla.org/feed/"),
        ("LWN", "https://lwn.net/headlines/rss"),
    ],
}
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GITHUB_ADVISORIES_URL = "https://api.github.com/advisories"
HN_API = "https://hacker-news.firebaseio.com/v0"
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().isoformat(timespec="seconds")


def clean(value: Any) -> str:
    if value is None:
        return ""
    value = html.unescape(str(value))
    value = re.sub(r"<[^>]+>", " ", value)
    return re.sub(r"\s+", " ", value).strip()


def parse_date(entry: Any) -> str:
    for key in ("published_parsed", "updated_parsed"):
        raw = entry.get(key)
        if raw:
            try:
                return datetime(*raw[:6], tzinfo=timezone.utc).isoformat(timespec="seconds")
            except Exception:
                pass
    return iso_now()


def connect() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH, timeout=20)
    con.row_factory = sqlite3.Row
    return con


def init_db() -> None:
    with connect() as con:
        con.execute("""
        CREATE TABLE IF NOT EXISTS articles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            source TEXT NOT NULL,
            category TEXT NOT NULL,
            published TEXT NOT NULL,
            summary TEXT DEFAULT '',
            severity TEXT DEFAULT '',
            is_kev INTEGER DEFAULT 0,
            cves TEXT DEFAULT '',
            ai_summary TEXT DEFAULT '',
            fetched TEXT NOT NULL
        )""")
        con.execute("CREATE INDEX IF NOT EXISTS idx_articles_published ON articles(published)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_articles_category ON articles(category)")
        con.execute("""
        CREATE TABLE IF NOT EXISTS kev (
            cve_id TEXT PRIMARY KEY,
            vendor TEXT DEFAULT '',
            product TEXT DEFAULT '',
            name TEXT DEFAULT '',
            description TEXT DEFAULT '',
            date_added TEXT DEFAULT '',
            due_date TEXT DEFAULT '',
            required_action TEXT DEFAULT '',
            ransomware_use TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            updated TEXT NOT NULL
        )""")
        con.execute("""
        CREATE TABLE IF NOT EXISTS advisories (
            ghsa_id TEXT PRIMARY KEY,
            cve_id TEXT DEFAULT '',
            summary TEXT DEFAULT '',
            severity TEXT DEFAULT '',
            url TEXT DEFAULT '',
            published TEXT DEFAULT '',
            updated TEXT NOT NULL
        )""")


def upsert_article(item: dict[str, Any]) -> bool:
    title = clean(item.get("title"))
    link = str(item.get("url", "")).strip()
    if not title or not link.startswith(("http://", "https://")):
        return False
    cves = sorted(set(CVE_RE.findall(title + " " + str(item.get("summary", "")))))
    severity = (item.get("severity") or "").upper()
    is_kev = int(bool(item.get("is_kev", False)))
    with connect() as con:
        cur = con.execute("""
        INSERT INTO articles(url,title,source,category,published,summary,severity,is_kev,cves,ai_summary,fetched)
        VALUES(?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(url) DO UPDATE SET
          title=excluded.title, summary=excluded.summary,
          severity=CASE WHEN excluded.severity != '' THEN excluded.severity ELSE articles.severity END,
          is_kev=MAX(articles.is_kev, excluded.is_kev),
          cves=CASE WHEN excluded.cves != '' THEN excluded.cves ELSE articles.cves END
        """, (
            link, title, item.get("source", "Unknown"), item.get("category", "Technology"),
            item.get("published") or iso_now(), clean(item.get("summary", ""))[:2000],
            severity, is_kev, ", ".join(cves), item.get("ai_summary", ""), iso_now()
        ))
        return cur.rowcount > 0


def fetch_feed(category: str, source: str, url: str) -> tuple[int, int]:
    """Fetch one RSS/Atom source with short timeouts and one bounded retry."""
    last_error = None
    for attempt in range(RETRY_COUNT + 1):
        try:
            # A per-request Session avoids sharing mutable Session state across worker threads.
            with requests.Session() as session:
                session.headers.update({"User-Agent": USER_AGENT, "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*"})
                response = session.get(url, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT))
                if response.status_code == 429 or response.status_code >= 500:
                    response.raise_for_status()
                response.raise_for_status()
                parsed = feedparser.parse(response.content)
            added = seen = 0
            for entry in parsed.entries[:80]:
                title = clean(entry.get("title", ""))
                link = str(entry.get("link", "")).strip()
                if not title or not link.startswith(("http://", "https://")):
                    continue
                summary = clean(entry.get("summary", entry.get("description", "")))[:2000]
                item = {
                    "title": title, "url": link, "source": source, "category": category,
                    "published": parse_date(entry), "summary": summary
                }
                seen += 1
                added += int(upsert_article(item))
            if parsed.bozo and not parsed.entries:
                print(f"[feed warning] {source}: invalid/empty feed")
            return added, seen
        except (requests.Timeout, requests.ConnectionError, requests.HTTPError) as exc:
            last_error = exc
            retryable = isinstance(exc, (requests.Timeout, requests.ConnectionError)) or (
                isinstance(exc, requests.HTTPError) and exc.response is not None and
                (exc.response.status_code == 429 or exc.response.status_code >= 500)
            )
            if attempt < RETRY_COUNT and retryable:
                time.sleep(0.4 * (attempt + 1))
                continue
            break
        except Exception as exc:
            last_error = exc
            break
    print(f"[feed warning] {source}: {type(last_error).__name__ if last_error else 'FetchError'} (skipped after bounded retry)")
    return 0, 0


def fetch_hacker_news(limit: int = 35) -> tuple[int, int]:
    try:
        response = SESSION.get(f"{HN_API}/topstories.json", timeout=(CONNECT_TIMEOUT, READ_TIMEOUT))
        response.raise_for_status()
        ids = response.json()[:limit]
    except Exception as exc:
        print(f"[HN warning] {type(exc).__name__}")
        return 0, 0
    added = seen = 0
    for item_id in ids:
        try:
            response = SESSION.get(f"{HN_API}/item/{item_id}.json", timeout=(CONNECT_TIMEOUT, READ_TIMEOUT))
            response.raise_for_status()
            data = response.json() or {}
            title = clean(data.get("title", ""))
            if not title:
                continue
            link = data.get("url") or f"https://news.ycombinator.com/item?id={item_id}"
            published = datetime.fromtimestamp(data.get("time", time.time()), timezone.utc).isoformat(timespec="seconds")
            seen += 1
            added += int(upsert_article({
                "title": title, "url": link, "source": "Hacker News API",
                "category": "Technology", "published": published,
                "summary": f"Score: {data.get('score', 0)} | Comments: {data.get('descendants', 0)}"
            }))
        except Exception:
            continue
    return added, seen


def fetch_kev() -> int:
    """Fetch CISA's official Known Exploited Vulnerabilities JSON catalog."""
    try:
        response = SESSION.get(CISA_KEV_URL, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT))
        response.raise_for_status()
        payload = response.json()
        records = payload.get("vulnerabilities", [])
    except Exception as exc:
        print(f"[KEV warning] {type(exc).__name__}")
        return 0
    count = 0
    with connect() as con:
        for v in records:
            cve = (v.get("cveID") or "").upper()
            if not cve:
                continue
            con.execute("""
            INSERT INTO kev(cve_id,vendor,product,name,description,date_added,due_date,
                            required_action,ransomware_use,notes,updated)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(cve_id) DO UPDATE SET
              vendor=excluded.vendor, product=excluded.product, name=excluded.name,
              description=excluded.description, date_added=excluded.date_added,
              due_date=excluded.due_date, required_action=excluded.required_action,
              ransomware_use=excluded.ransomware_use, notes=excluded.notes, updated=excluded.updated
            """, (
                cve, v.get("vendorProject", ""), v.get("product", ""),
                v.get("vulnerabilityName", ""), v.get("shortDescription", ""),
                v.get("dateAdded", ""), v.get("dueDate", ""), v.get("requiredAction", ""),
                v.get("knownRansomwareCampaignUse", ""), v.get("notes", ""), iso_now()
            ))
            count += 1
    # Mark already-collected stories whose title/summary contains a KEV CVE.
    with connect() as con:
        kev_rows = con.execute("SELECT cve_id FROM kev").fetchall()
        for row in kev_rows:
            cve = row["cve_id"]
            con.execute("""
                UPDATE articles SET is_kev=1, category='Cybersecurity'
                WHERE upper(title || ' ' || summary) LIKE ?
            """, (f"%{cve}%",))
        # Add each KEV as a first-class story for the dashboard even if no RSS source mentions it.
        for v in records[:300]:
            cve = (v.get("cveID") or "").upper()
            title = f"[KNOWN EXPLOITED] {cve}: {v.get('vulnerabilityName', 'Vulnerability')}"
            url = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve}"
            con.execute("""
            INSERT OR IGNORE INTO articles(url,title,source,category,published,summary,severity,is_kev,cves,ai_summary,fetched)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)
            """, (
                url, title, "CISA Known Exploited Vulnerabilities", "Cybersecurity",
                v.get("dateAdded", iso_now()), clean(v.get("shortDescription", "")),
                "CRITICAL", 1, cve, "", iso_now()
            ))
    return count


def fetch_github_advisories(limit: int = 50) -> int:
    try:
        response = SESSION.get(
            GITHUB_ADVISORIES_URL,
            params={"per_page": min(limit, 100), "type": "reviewed"},
            headers={"Accept": "application/vnd.github+json"},
            timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
        )
        response.raise_for_status()
        items = response.json()
    except Exception as exc:
        print(f"[GitHub advisory warning] {type(exc).__name__}")
        return 0
    added = 0
    for item in items:
        severity = (item.get("severity") or "").upper()
        ghsa = item.get("ghsa_id") or ""
        cve = item.get("cve_id") or ""
        title = f"[{severity or 'UNRATED'}] {item.get('summary') or ghsa}"
        summary = f"GHSA: {ghsa} | CVE: {cve or 'Not assigned'}"
        url = item.get("html_url") or ""
        published = item.get("published_at") or iso_now()
        if url:
            added += int(upsert_article({
                "title": title, "url": url, "source": "GitHub Advisory Database",
                "category": "Cybersecurity", "published": published,
                "summary": summary, "severity": severity,
            }))
        if ghsa:
            with connect() as con:
                con.execute("""
                INSERT INTO advisories(ghsa_id,cve_id,summary,severity,url,published,updated)
                VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(ghsa_id) DO UPDATE SET
                cve_id=excluded.cve_id,summary=excluded.summary,severity=excluded.severity,
                url=excluded.url,published=excluded.published,updated=excluded.updated
                """, (ghsa, cve, clean(item.get("summary", "")), severity, url, published, iso_now()))
    return added


def refresh_all() -> dict[str, Any]:
    if not refresh_lock.acquire(blocking=False):
        return {"status": "already_running", "added": 0}
    try:
        total_added = total_seen = 0
        jobs = []
        for category, sources in FEEDS.items():
            for source, feed_url in sources:
                jobs.append((category, source, feed_url))

        # RSS sources run concurrently, so one slow publisher no longer blocks every source.
        with ThreadPoolExecutor(max_workers=MAX_FEED_WORKERS, thread_name_prefix="techintel-feed") as pool:
            futures = {
                pool.submit(fetch_feed, category, source, feed_url): source
                for category, source, feed_url in jobs
            }
            for future in as_completed(futures):
                source = futures[future]
                try:
                    added, seen = future.result()
                    total_added += added
                    total_seen += seen
                except Exception as exc:
                    print(f"[feed warning] {source}: {type(exc).__name__} (worker skipped)")

        # API collectors also have bounded network timeouts and are isolated from RSS failures.
        added, seen = fetch_hacker_news()
        total_added += added
        total_seen += seen
        kev_count = fetch_kev()
        gh_added = fetch_github_advisories()
        total_added += gh_added
        return {
            "status": "ok", "added": total_added, "processed": total_seen,
            "kev_count": kev_count, "github_advisories_added": gh_added,
            "updated": iso_now()
        }
    finally:
        refresh_lock.release()


def get_articles(
    q: str = "", category: str = "All", source: str = "All",
    priority: str = "All", period: str = "All", limit: int = 100
) -> list[dict[str, Any]]:
    sql = "SELECT * FROM articles WHERE 1=1"
    params: list[Any] = []
    if q:
        sql += " AND (lower(title) LIKE ? OR lower(summary) LIKE ? OR lower(source) LIKE ? OR lower(cves) LIKE ?)"
        term = f"%{q.lower()}%"
        params.extend([term, term, term, term])
    if category != "All":
        sql += " AND category = ?"
        params.append(category)
    if source != "All":
        sql += " AND source = ?"
        params.append(source)
    if priority == "Critical":
        sql += " AND (is_kev=1 OR severity='CRITICAL')"
    elif priority == "High+":
        sql += " AND (is_kev=1 OR severity IN ('CRITICAL','HIGH'))"
    elif priority == "KEV":
        sql += " AND is_kev=1"
    elif priority == "Rated":
        sql += " AND severity != ''"
    if period == "24 hours":
        sql += " AND published >= ?"
        params.append((utc_now() - timedelta(hours=24)).isoformat())
    elif period == "7 days":
        sql += " AND published >= ?"
        params.append((utc_now() - timedelta(days=7)).isoformat())
    sql += """
        ORDER BY is_kev DESC,
        CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MODERATE' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END DESC,
        published DESC LIMIT ?
    """
    params.append(max(1, min(limit, 500)))
    with connect() as con:
        return [dict(r) for r in con.execute(sql, params).fetchall()]


def get_article(article_id: int) -> dict[str, Any] | None:
    with connect() as con:
        row = con.execute("SELECT * FROM articles WHERE id=?", (article_id,)).fetchone()
    return dict(row) if row else None


def make_fallback_summary(article: dict[str, Any]) -> str:
    """Useful structured fallback when no local AI model is configured."""
    title = article.get("title", "This story")
    description = clean(article.get("summary", ""))
    category = article.get("category", "Technology")
    source = article.get("source", "the publisher")
    text = description or f"The headline reports: {title}."
    text = text[:650].strip()
    if article.get("is_kev"):
        impact = "CISA lists this CVE as known exploited in the wild. Organizations using the affected product should identify exposure and follow the vendor's official remediation guidance promptly."
    elif article.get("severity") in ("CRITICAL", "HIGH"):
        impact = f"The advisory is rated {article.get('severity')}. Users and teams running the affected software should check the original advisory for affected versions, mitigations and available patches."
    elif category == "Cybersecurity":
        impact = "Security teams should verify the details against the original source, check whether their systems are affected, and apply vendor guidance where relevant."
    else:
        impact = "The practical impact depends on the product, release details and who uses it. Read the original source before making technical or business decisions."
    return (
        f"WHAT HAPPENED\n{text}\n\n"
        f"WHY IT MATTERS\nThis update was published by {source}. {impact}\n\n"
        f"WHO IS AFFECTED\n"
        f"{'Potentially organizations and users of the named vulnerable product; confirm exact versions in the source.' if category == 'Cybersecurity' else 'People and teams following ' + category.lower() + ', especially users or developers of the product or technology named in the article.'}\n\n"
        "EDITORIAL NOTE\nThis is an automated briefing aid, not independent verification. Confirm claims and affected versions in the linked original source."
    )


def ai_summary(article: dict[str, Any], force: bool = False) -> tuple[str, str]:
    """Use local Ollama when available; never requires a cloud API key."""
    if article.get("ai_summary") and not force:
        return article["ai_summary"], "cached"
    prompt = textwrap.dedent(f"""
        You are a careful technology and cybersecurity news editor.
        Use ONLY the supplied article metadata and excerpt. Do not invent facts, dates,
        affected versions, exploit details, quotes, or claims. If details are missing, say
        they are not specified in the supplied excerpt. Write concise plain text with exactly
        these headings:
        WHAT HAPPENED
        WHY IT MATTERS
        WHO IS AFFECTED
        Include a short practical implication. Do not provide exploit instructions.
        Title: {article.get('title','')}
        Publisher: {article.get('source','')}
        Category: {article.get('category','')}
        Severity: {article.get('severity','not specified')}
        CISA KEV listed: {'yes' if article.get('is_kev') else 'no/unknown'}
        Excerpt: {clean(article.get('summary',''))[:1500]}
    """).strip()
    try:
        response = SESSION.post(
            OLLAMA_URL,
            json={"model": os.getenv("OLLAMA_MODEL", "qwen2.5:3b"), "prompt": prompt, "stream": False},
            timeout=90,
        )
        response.raise_for_status()
        result = clean(response.json().get("response", ""))
        if not result:
            raise ValueError("empty model response")
        with connect() as con:
            con.execute("UPDATE articles SET ai_summary=? WHERE id=?", (result, article["id"]))
        return result, "ollama"
    except Exception:
        return make_fallback_summary(article), "fallback"


def build_digest() -> Path:
    now = utc_now()
    rows = get_articles(period="24 hours", limit=500)
    critical = [r for r in rows if r.get("is_kev") or r.get("severity") in ("CRITICAL", "HIGH")]
    cyber = [r for r in rows if r.get("category") == "Cybersecurity"]
    tech = [r for r in rows if r.get("category") != "Cybersecurity"]
    lines = [
        f"# z4dsu Morning Briefing | {now.strftime('%Y-%m-%d')}",
        "",
        f"Generated at {now.strftime('%H:%M UTC')}. This briefing summarizes items collected in the last 24 hours.",
        "",
        "## Editor's overview",
        f"- {len(rows)} stories collected.",
        f"- {len(critical)} high-priority security items (including CISA KEV entries where available).",
        f"- {len(cyber)} cybersecurity stories and {len(tech)} broader tech/developer stories.",
        "",
        "## Priority security alerts",
    ]
    if critical:
        for item in critical[:15]:
            marker = " **KNOWN EXPLOITED (CISA KEV)**" if item.get("is_kev") else f" **{item.get('severity') or 'HIGH PRIORITY'}**"
            lines.extend([
                f"### {item['title']}{marker}",
                f"- Source: {item['source']}",
                f"- Published: {item['published']}",
                f"- Link: {item['url']}",
                f"- Note: {item['summary'] or 'Open the source for full details.'}",
                ""
            ])
    else:
        lines.extend(["No high-priority items were detected in the locally collected 24-hour window.", ""])
    lines.extend(["## Cybersecurity", ""])
    for item in cyber[:15]:
        lines.append(f"- [{item['title']}]({item['url']}) · {item['source']}")
    lines.extend(["", "## Technology, launches and developer news", ""])
    for item in tech[:20]:
        lines.append(f"- [{item['title']}]({item['url']}) · {item['source']}")
    lines.extend([
        "", "## Verification reminder",
        "This is an automated source roundup, not a claim that every item has been independently verified. Check the original publisher and vendor advisory before publishing or taking action.",
        ""
    ])
    path = DIGEST_DIR / f"z4dsu-digest-{now.strftime('%Y-%m-%d')}.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


@app.template_filter("prettydate")
def prettydate(value: str) -> str:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone().strftime("%d %b %Y, %I:%M %p")
    except Exception:
        return value or "Unknown date"


@app.template_filter("severity_class")
def severity_class(value: str) -> str:
    return (value or "unrated").lower()


@app.route("/")
def index():
    q = request.args.get("q", "").strip()[:160]
    category = request.args.get("category", "All")
    source = request.args.get("source", "All")
    priority = request.args.get("priority", "All")
    period = request.args.get("period", "All")
    allowed_categories = {"All", *FEEDS.keys()}
    if category not in allowed_categories:
        category = "All"
    if priority not in {"All", "Critical", "High+", "KEV", "Rated"}:
        priority = "All"
    if period not in {"All", "24 hours", "7 days"}:
        period = "All"
    with connect() as con:
        sources = [r["source"] for r in con.execute("SELECT DISTINCT source FROM articles ORDER BY source")]
        total = con.execute("SELECT COUNT(*) FROM articles").fetchone()[0]
        kev_count = con.execute("SELECT COUNT(*) FROM articles WHERE is_kev=1").fetchone()[0]
        critical_count = con.execute("SELECT COUNT(*) FROM articles WHERE severity IN ('CRITICAL','HIGH') OR is_kev=1").fetchone()[0]
        latest = con.execute("SELECT MAX(fetched) FROM articles").fetchone()[0]
    if source not in {"All", *sources}:
        source = "All"
    articles = get_articles(q, category, source, priority, period)
    return render_template(
        "index.html", articles=articles, q=q, category=category, source=source,
        priority=priority, period=period, categories=["All", *FEEDS.keys()],
        sources=sources, total=total, kev_count=kev_count,
        critical_count=critical_count, latest=latest
    )


@app.post("/refresh")
def refresh_route():
    result = refresh_all()
    if result["status"] == "already_running":
        flash("A refresh is already running.", "warning")
    else:
        flash(
            f"Refresh finished: {result['added']} new items; CISA KEV catalog has {result['kev_count']} entries.",
            "success"
        )
    return redirect(request.referrer or url_for("index"))


@app.route("/article/<int:article_id>")
def article_detail(article_id: int):
    article = get_article(article_id)
    if not article:
        abort(404)
    return render_template("article.html", article=article)


@app.post("/article/<int:article_id>/summarize")
def summarize_route(article_id: int):
    article = get_article(article_id)
    if not article:
        abort(404)
    summary, mode = ai_summary(article, force=True)
    if mode == "fallback":
        flash("Local AI model unavailable. Showing a structured fallback summary. Install Ollama for generated summaries.", "warning")
    else:
        flash("Summary generated with your local Ollama model.", "success")
    return render_template("article.html", article=article, summary=summary, summary_mode=mode)


@app.post("/digest")
def digest_route():
    path = build_digest()
    flash(f"Morning briefing generated: {path.name}", "success")
    return send_file(path, as_attachment=True, download_name=path.name, mimetype="text/markdown")


@app.get("/api/status")
def status():
    with connect() as con:
        count = con.execute("SELECT COUNT(*) FROM articles").fetchone()[0]
        kev = con.execute("SELECT COUNT(*) FROM kev").fetchone()[0]
        latest = con.execute("SELECT MAX(fetched) FROM articles").fetchone()[0]
    return {"articles": count, "kev_catalog_entries": kev, "latest_fetch": latest}


def cli() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="z4dsu web dashboard")
    parser.add_argument("--refresh", action="store_true", help="refresh feeds and exit")
    parser.add_argument("--digest", action="store_true", help="generate today's Markdown digest and exit")
    args = parser.parse_args()
    init_db()
    if args.refresh:
        print(refresh_all())
        return
    if args.digest:
        print(f"Digest written to: {build_digest()}")
        return
    print(f"z4dsu dashboard: http://{APP_HOST}:{APP_PORT}")
    app.run(host=APP_HOST, port=APP_PORT, debug=False, threaded=True)


if __name__ == "__main__":
    init_db()
    cli()
