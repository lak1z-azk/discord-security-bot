# 🛡️ Discord Security Bot

A powerful, modern Discord security and moderation bot focused on automatic URL scanning, anti-phishing, malicious domain blocklisting, AI-driven threat analysis, and advanced auto-moderation features for your community.  
Supports interactive, multi-step setup per server, flexible configuration, and persistent MySQL storage for logging and threat tracking.

**Note: This project is still in its early testing phase!**  
Initial results are positive, but more feedback and real-world usage are needed. If you have any issues, questions, or suggestions about how the bot works, please use [GitHub Issues](https://github.com/lak1z-azk/wolf-guard/issues) — I will do my best to answer as soon as possible.

This is my first time building this kind of modular, persistent security structure for Discord servers. My main motivation is that phishing, scam, and malware attacks are getting out of control on Discord — and many people are still being caught. This bot is my way to help put a stop to that.

---

## 🚨 Important Requirements & Notes

- **VirusTotal API:**  
  To fully use automatic URL scanning, you need to register for a [VirusTotal account](https://www.virustotal.com/gui/join-us) and get an API key.  
  *The free API is limited (4 requests/minute, 500/day), but this is enough for most community servers.*
- **LLM/Ollama Support (Optional):**  
  If you want detailed AI threat summaries, set up [Ollama](https://ollama.com/) locally and provide the API endpoint in your `.env`.  
  This is not required, but will provide better analysis and reporting for server owners and admins.
- **Discord Bot Application:**  
  You **must** create your own Discord bot application at [Discord Developer Portal](https://discord.com/developers/applications), copy your bot token, and invite the bot to your server with appropriate permissions.
- **Setup Permissions:**  
  *Currently, only the server owner is able to run the initial setup wizard.*  
  (If you want to let admins do it too, let me know — this can be changed.)

---

## ✨ Features

- **Malicious URL Detection:** Scans all posted links with VirusTotal and a local blocklist.  
- **Automatic Action:** Deletes messages and can auto-kick users who post malicious URLs (configurable).  
- **AI-Powered Analysis:** Integrates with local LLM/Ollama API for threat summaries.  
- **Security Logging:** Posts detailed incident reports to a chosen server log channel.  
- **Role-Based Controls:** Immune roles, admin roles, and granular permission settings.  
- **Rate Limiting:** API call limits for safe, efficient VirusTotal usage.  
- **Persistent Storage:** Uses MySQL for all data: blocklists, logs, statistics, and server configs.  
- **Multi-Server Support:** Fully supports running in many servers, with per-server configuration.

---

## 🚀 Quick Start

### 1. **Clone & Install**
```git clone https://github.com/lak1z-azk/wolf-guard.git
cd discord-security-bot
npm install
```

### 2. Configure Environment
Create a .env file (see .env.example if present):
```
DISCORD_TOKEN=your-bot-token
DB_HOST=localhost
DB_USER=your-db-user
DB_PASSWORD=your-db-password
DB_NAME=your-db-name
VIRUSTOTAL_API_KEY=your-virustotal-key   # optional, but highly recommended
OLLAMA_SERVER_URL=http://localhost:11434/api   # for AI summaries (optional)
VT_RATE_LIMIT=4
VT_DAILY_LIMIT=500
CACHE_DURATION_HOURS=24
MAX_CACHE_SIZE=1000
```
Note:
- VirusTotal API is strongly recommended for full protection, but bot works in "limited mode" without it.
- Make sure MySQL is running and accessible with your credentials.

### 3. Start the Bot
```node src/index.js```
### 🛠️ Database Setup
The bot will automatically create required tables on first launch, including:
- blockedList: Persistent malicious domain blocklist
- blockedMessages: Log of every blocked/threat message
- url_scan_cache: Caches all scan results (reduces API usage)
- server_config: Per-server configuration (log channels, roles, settings)
- bot_stats: Daily stats
- security_events: All important events (incidents, actions)
- user_warnings: (Optional, for future warning/tracking features)
- You can review the table definitions in src/db.js.

# ⚡ Server Setup & Configuration
Once you invite the bot, it does not need any manual config files or editing—everything is handled via Discord’s UI.

## Interactive Setup Wizard
### Trigger setup:
- The bot will DM the server owner when added.
### Setup Steps:
- Select a Log Channel for security reports.
- Choose Admin Roles (who can manage the bot and view logs).
- Choose Immune Roles (users/roles never scanned or auto-moderated).
- Configure Actions: Enable/disable auto-kick, message deletion, scanning.
- Review & Confirm all settings.
- Setup is per-server. Each community configures the bot separately!

### Changing Configuration
- Re-run the setup wizard at any time to update log channel, permissions, or actions.
- Admins and configured admin roles can access the setup.

### 🔗 Security Actions & Moderation
- Scans every link: Checks against blocklist and VirusTotal (if enabled).
- Auto-kick (optional): Users posting malicious links can be auto-removed.
- Auto-delete: Malicious messages are deleted instantly.
- Security events are logged: Every incident, kick, or suspicious action is reported to the configured channel.

# 📊 Statistics & Logging
All security actions are logged to your chosen channel and MySQL database.
- Stats: The bot tracks threats detected, users kicked, links scanned, and more.
- Cache: Results are cached (duration configurable) for performance and lower API usage.

# 👮‍♂️ Permissions
The bot requires these permissions:
- View Channels
- Send Messages
- Embed Links
- Manage Messages (for auto-deleting threats)
- Kick Members (for auto-kicking malicious users)
- Read Message History (for deleting user messages)
- It’s recommended to grant only the permissions you actually need in your server.
- 💡 Advanced Features
- Local blocklist: Easily expand with your own known malicious domains.
- AI threat summaries: If using Ollama/LLM, threat reports get extra AI-powered summaries.
- Rate limiting: Ensures your VirusTotal API quota isn’t exhausted.

# 🛑 Troubleshooting
### Bot won’t start?
- Check your .env for correct Discord token and database credentials.
- Ensure MySQL is running and accessible.
###  Not responding to setup?
- Make sure you (or the user running setup) have Administrator permission.
### VirusTotal not working?
- Check your API key and rate limits.
- The bot will run in limited mode without a key, but detection is less accurate.

# 🧑‍💻 Contributing
- Pull requests are welcome!
- If you find bugs or have suggestions, open an issue or PR.

# 📜 License
MIT License
(c) 2024 [Your Name or Organization]

Stay secure, and keep your community safe!

---

### How to Import the Blocklist (Recommended Method)

1. Make sure `malicious_urls.csv` (with 10,000+ entries) is present in your bot directory or on your computer.
2. Open your database tool (for example, **DBeaver**, HeidiSQL, MySQL Workbench, etc.).
3. Connect to your bot’s MySQL database.
4. Locate/select the `blockedList` table.
5. Use the **Import Data** feature to import from CSV.
    - In DBeaver:  
      - Right-click the `blockedList` table → select **Import Data** (see screenshot below).
      - Choose **CSV** as the import source, select `malicious_urls.csv`, and follow the prompts.
    - Make sure the CSV column is mapped to the `list` column in the `blockedList` table.
6. Complete the import wizard and commit changes.

**Keep your community protected by importing the latest blocklist regularly!**

---

## 🧪 Testing & Best Practices

**Before deploying this bot to your main community, it’s strongly recommended to:**

- **Create a separate Discord account** (or use an alt/test account).
- **Set up a private Discord test server** where you have full admin control.
- **Invite the bot** to this test server and run through the full setup process.
- **Simulate real attacks:**  
  - Try posting known phishing or scam URLs (from the blocklist or VirusTotal) to see how the bot responds.
  - Test permissions, role setups, and logging to make sure everything works as expected.

> **Why?**  
> This will help you understand the bot’s functionality, ensure you’re comfortable with all features, and avoid surprises on your main server.

**If you find any bugs, unclear behavior, or missing features, please open an issue here on GitHub!**  
Feedback from testing is what makes this project better for everyone.

---
