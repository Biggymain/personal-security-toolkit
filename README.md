# Personal Security Toolkit

A combined set of personal security tools for **phone OSINT** and **offline password auditing**.

---

## Features

### 1. Breach Monitor (Phone OSINT)
- Checks phone numbers using **PhoneInfoga** and **NumberVerify**.
- Sends structured alerts to your **Telegram** chat.
- Logs findings to a local file for tracking.

### 2. Password Audit (Offline-Friendly)
- Evaluates password strength using length, character variety, and entropy.
- Checks passwords against **local Pwned Passwords range files** (k-anonymity SHA-1 format).
- Uses a local **SQLite breach database** for offline breach checking.
- Completely offline after datasets are downloaded — no password leaks.
---

## Installation & Setup

1. **Clone the repository**
```bash
git clone https://github.com/Biggymain/personal-security-toolkit.git
cd personal-security-toolkit
````

2. **Create a Python virtual environment** (recommended)

```bash
python3 -m venv .venv
source .venv/bin/activate
```

3. **Install dependencies**

```bash
pip install requests python-dotenv python-telegram-bot schedule
```

4. **Set up API keys**

```bash
cp .env.example .env
nano .env
```

* Fill in your `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, and `NUMBERVERIFY_API_KEY`.

5. **Prepare Pwned Passwords range files** (for password auditing)

* Download from [Have I Been Pwned Pwned Passwords](https://haveibeenpwned.com/Passwords)
* Place `.txt` files in `pwned_ranges/`.

6. **Optional: Build a local breach database**

```bash
cd password-audit
python3 pw_audit.py index-breaches --breach-dir ./breach_plaintext_dir --db ./breach_pw.sqlite
```

---

## Usage

### **1. Phone OSINT (Breach Monitor)**

```bash
cd breach-monitor
source ../.venv/bin/activate
python3 Monitor_report.py
```

* Enter phone numbers when prompted.
* Telegram alerts are sent automatically.

### **2. Password Audit (Single Password)**

```bash
cd password-audit
python3 pw_audit.py check --pwned-range-dir ../pwned_ranges --breach-db ./breach_pw.sqlite
```

* Enter the password interactively when prompted.

### **3. Password Audit (From File)**

```bash
python3 pw_audit.py check-file passwords.txt --pwned-range-dir ../pwned_ranges --breach-db ./breach_pw.sqlite
```

* Checks each password in the file.

---

## Security Notes

* **Never commit `.env` with real API keys** — only `.env.example`.
* Password checks are offline using SHA-1 hashes; your plaintext passwords are never sent anywhere.
* Use strong passwords and consider passphrases for maximum entropy.

---

## License

MIT License — free to use, modify, and distribute.
