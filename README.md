# z4dsu

A local-first web dashboard for technology and cybersecurity news. It preserves the original free RSS/API sources and adds searchable filters, dark/light mode, local AI summaries (optional), CISA KEV prioritization, and a Markdown morning digest.

## Features
- Responsive Flask dashboard with search, category, source, time-window and severity filters.
- Dark/light theme toggle, saved in the browser.
- Free RSS/Atom feeds plus Hacker News public API and GitHub Advisory Database public API.
- CISA Known Exploited Vulnerabilities (KEV) official JSON catalog. KEV entries are prominently marked and prioritized.
- GitHub advisory severity tags (when provided by GitHub).
- Article explainer: WHAT HAPPENED / WHY IT MATTERS / WHO IS AFFECTED.
- Optional local AI using Ollama. No cloud AI API key is needed. If Ollama is not installed/running, the app shows a cautious structured fallback rather than failing.
- Daily digest export as Markdown, with priority alerts and story links.
- SQLite local database. No user account or hosted service required.

## Windows setup
Install Python 3.10+ first. Extract the ZIP, open the extracted folder in File Explorer, type `cmd` in the address bar and press Enter.

```bat
py -m venv .venv
.venv\Scripts\activate
py -m pip install -r requirements.txt
py app.py
```

Open http://127.0.0.1:5000 in your browser. Click **Refresh feeds** on the dashboard to collect updates. First refresh can take a minute or two.

If `py` is not recognized, try `python` instead. If Flask says the port is in use, set another port before starting:
```bat
set TECHINTEL_PORT=5050
py app.py
```

## Enable local AI summaries (optional)
1. Install Ollama from https://ollama.com/download.
2. Open a new terminal and run:
```bat
ollama pull qwen2.5:3b
```
3. Keep Ollama running and restart/refresh z4dsu. The default model is `qwen2.5:3b`.
4. To use another model, set `OLLAMA_MODEL` before launching:
```bat
set OLLAMA_MODEL=llama3.2:3b
py app.py
```

Ollama runs the model locally. It may use considerable RAM/CPU; if your computer is older or has limited memory, summaries may be slow. The fallback mode requires no AI model or extra API key. Summaries use only available feed excerpts and metadata and can miss important details.

## Daily morning digest
- On the dashboard, click **Morning digest**. A `.md` file is generated and downloaded.
- Or generate it from the terminal:
```bat
py app.py --digest
```
- Refresh sources first for a fresher digest:
```bat
py app.py --refresh
py app.py --digest
```

### Automate daily on Windows
Use Windows Task Scheduler:
1. Open **Task Scheduler** → **Create Basic Task**.
2. Name it `z4dsu Morning Digest`, choose **Daily**, and select your morning time.
3. Action: **Start a program**.
4. Program/script: path to your Python executable (find it with `where python` while the venv is active, or use the `.venv\\Scripts\\python.exe` path).
5. Add arguments: `app.py --refresh` and set **Start in** to the extracted project folder. This refresh task collects data.
6. Create a second daily task for `app.py --digest` a few minutes later. Set **Start in** to the same project folder. The Markdown digest is saved in the `digests` subfolder.
7. Optional: add `--digest` task after refresh. It writes a file but does not send email or post online.

## Prioritization notes
- CISA KEV means the vulnerability appears in CISA's Known Exploited Vulnerabilities catalog, which is evidence of exploitation in the wild. It is a prioritization signal, not proof that your own device is compromised.
- A vulnerability not in KEV may still be serious. The tool marks known GitHub severities as supplied; it does not invent CVSS scores.
- CISA KEV is authoritative data from the official public JSON catalog: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- CISA catalog records are ingested as priority story cards. The first 300 entries are represented as dashboard stories on each refresh; all entries are stored in the `kev` table and can flag matching CVE mentions from feeds.
- The dashboard is for personal awareness and editorial research, not a replacement for vendor advisories or a complete vulnerability scanner.

## Troubleshooting
- If some feeds fail, the app logs a short warning and continues. Feed formats and URLs can change.
- If the page is empty, click **Refresh feeds**.
- If summaries show “structured fallback,” Ollama is unavailable or the model is not installed. The dashboard still works.
- Delete `techintel.db` only if you intentionally want to erase the local article cache and start fresh.
- Do not expose the Flask development server to the public internet. It is intended for localhost use.


## Refresh performance (optimized)
- RSS/Atom feeds are fetched concurrently with up to 10 worker threads.
- Each feed uses a 4-second connection timeout and 8-second read timeout.
- A single retry is attempted for connection/timeouts and temporary HTTP 429/5xx responses, with a short backoff; permanently failing feeds are skipped.
- Existing `techintel.db` is reused. This update does not delete or recreate the database.
- Some API calls and the CISA KEV processing still run after the RSS batch, so total refresh time depends on network quality and source response times.
