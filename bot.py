import os
import re
import requests
import subprocess
import zipfile
import tempfile
import aiohttp
import dns.resolver
from pathlib import Path
from urllib.parse import urlparse, parse_qsl
from telegram import Update, InputFile
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, ContextTypes, filters
from dotenv import load_dotenv

load_dotenv()

TELEGRAM_API_TOKEN = os.getenv('TELEGRAM_API_TOKEN')

# Validate domain input safely
def extract_domain(text: str) -> str:
    try:
        # Extract domain from URL or plain domain
        text = text.strip().lower()
        if not text.startswith("http"):
            text = "http://" + text
        parsed = urlparse(text)
        domain = parsed.netloc
        # Basic domain pattern validation
        if re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", domain):
            return domain
    except Exception:
        return None
    return None

# Fetch robots.txt if exists
def fetch_robots(domain: str, folder_path: Path):
    url = f"https://{domain}/robots.txt"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200 and r.text.strip():
            (folder_path / "robots.txt").write_text(r.text)
    except Exception:
        pass

# Get subdomains by bruteforce / through online sources (here using crt.sh)
def fetch_subdomains(domain: str, folder_path: Path):
    subs_file = folder_path / "subs.txt"
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            data = r.json()
            subdomains = set()
            for cert in data:
                name = cert.get('name_value')
                if name:
                    # crt.sh may return multiline with \n between names
                    names = name.split("\n")
                    for n in names:
                        if domain in n:
                            subdomains.add(n.lower())
            if subdomains:
                subs_file.write_text("\n".join(sorted(subdomains)))
                return subs_file
    except Exception:
        pass
    # fallback empty file
    subs_file.write_text("")
    return subs_file

# Check live subdomains with simple HTTP request
async def fetch_live_subs(subs_path: Path, folder_path: Path):
    live_file = folder_path / "live-subs.txt"
    live_subs = []

    if not subs_path.exists():
        live_file.write_text("")
        return live_file

    subs = subs_path.read_text().splitlines()
    timeout = aiohttp.ClientTimeout(total=5)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        for sub in subs:
            https_url = f'https://{sub}'
            http_url = f'http://{sub}'
            try:
                async with session.get(https_url, allow_redirects=True) as resp:
                    if resp.status < 400:
                        live_subs.append(sub)
                        continue
            except Exception:
                try:
                    async with session.get(http_url, allow_redirects=True) as resp:
                        if resp.status < 400:
                            live_subs.append(sub)
                except Exception:
                    pass

    live_file.write_text("\n".join(live_subs))
    return live_file

# Get wayback URLs related to domain
def fetch_wayback_urls(domain: str, folder_path: Path):
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey"
    wayback_file = folder_path / "wayback.txt"
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            lines = r.text.strip().splitlines()
            unique_urls = sorted(set(lines))
            if unique_urls:
                wayback_file.write_text("\n".join(unique_urls))
                return wayback_file
    except Exception:
        pass
    wayback_file.write_text("")
    return wayback_file

# Extract URL parameters from wayback URLs
def extract_params(wayback_path: Path, folder_path: Path):
    params_file = folder_path / "params.txt"
    params = set()
    if not wayback_path.exists():
        params_file.write_text("")
        return params_file

    lines = wayback_path.read_text().splitlines()
    for url in lines:
        parsed = urlparse(url)
        qsl = parse_qsl(parsed.query)
        for key, val in qsl:
            if key and val:
                params.add(f"{key}={val}")
    if params:
        params_file.write_text("\n".join(sorted(params)))
    else:
        params_file.write_text("")
    return params_file

# Find JS files by crawling wayback URLs or using subdomains list and GET request for *.js
def fetch_js_files(domain: str, folder_path: Path):
    js_file_path = folder_path / "jsfiles.txt"
    js_files = set()

    # Quick approach: query wayback for .js files directly
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*.js&output=text&fl=original&collapse=urlkey"
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            lines = r.text.strip().splitlines()
            js_files.update(lines)
    except Exception:
        pass

    js_file_path.write_text("\n".join(sorted(js_files)) if js_files else "")
    return js_file_path

# Find potential secret keys in JS files content
def find_js_secrets(js_file_path: Path, folder_path: Path):
    secrets_file = folder_path / "js-secret.txt"
    secrets = set()
    js_urls = js_file_path.read_text().splitlines()
    secret_patterns = [
        re.compile(r"(?i)(apikey|secret|token|client_secret|password|access_key)[^=:\r\n]+[:=][^,\s'\"&]+")
    ]

    for url in js_urls:
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200 and r.text:
                content = r.text
                for pattern in secret_patterns:
                    found = pattern.findall(content)
                    for secret in found:
                        secrets.add(f"{url}: {secret}")
        except Exception:
            continue

    if secrets:
        secrets_file.write_text("\n".join(sorted(secrets)))
    else:
        secrets_file.write_text("")
    return secrets_file


# Command /start
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Hello! Send me a domain URL (example.com) and I will perform basic bug bounty recon for you.\n"
        "Use /help to see available commands."
    )


# Command /help
async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    help_text = (
        "Commands:\n"
        "/start - Start bot and instructions\n"
        "/help - Show this help message\n"
        "Send a domain URL to start reconnaissance.\n\n"
        "Example: example.com"
    )
    await update.message.reply_text(help_text)


# Main message handler: expects domain URL, performs recon and sends zipped results
async def handle_domain(update: Update, context: ContextTypes.DEFAULT_TYPE):
    domain_input = update.message.text
    domain = extract_domain(domain_input)
    if not domain:
        await update.message.reply_text(
            "❌ Invalid domain. Please send a valid domain URL, e.g., example.com"
        )
        return
    
    msg = await update.message.reply_text(f"🔍 Starting recon for domain: {domain}. This may take a minute...")

    with tempfile.TemporaryDirectory() as tmpdirname:
        folder_path = Path(tmpdirname)

        # Fetch basic recon data files
        fetch_robots(domain, folder_path)
        subs_path = fetch_subdomains(domain, folder_path)
        # Use async for live subs
        live_subs_path = await fetch_live_subs(subs_path, folder_path)
        wayback_path = fetch_wayback_urls(domain, folder_path)
        extract_params(wayback_path, folder_path)
        js_files_path = fetch_js_files(domain, folder_path)
        find_js_secrets(js_files_path, folder_path)

        # Create the zip
        zip_path = folder_path / "result.zip"
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file in folder_path.iterdir():
                if file.suffix != ".zip":
                    zipf.write(file, arcname=file.name)

        # Send notifier and zip file
        await msg.edit_text(f"✅ Recon finished for domain {domain}! Sending results.")
        await update.message.reply_document(document=InputFile(zip_path), filename="result.zip")


async def main():
    app = ApplicationBuilder().token(TELEGRAM_API_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(MessageHandler(filters.TEXT & (~filters.COMMAND), handle_domain))

    print("Bot started...")
    await app.run_polling()


if __name__ == '__main__':
    import asyncio
    asyncio.run(main())
