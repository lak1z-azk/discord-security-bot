# Security Bot Setup Guide for Linux (Ubuntu/Debian)

Complete installation and configuration guide for the Discord Security Bot on Ubuntu/Debian Linux servers.

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [System Requirements](#system-requirements)
- [Installation Steps](#installation-steps)
- [Database Setup](#database-setup)
- [Environment Configuration](#environment-configuration)
- [Bot Configuration](#bot-configuration)
- [Running the Bot](#running-the-bot)
- [Process Management](#process-management)
- [Monitoring & Maintenance](#monitoring--maintenance)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)

## 🔧 Prerequisites

### System Requirements
- **OS**: Ubuntu 20.04+ or Debian 11+
- **RAM**: Minimum 2GB (4GB recommended)
- **Storage**: 10GB free space
- **Network**: Internet connection for API calls
- **Ports**: 3306 (MySQL), 11434 (Ollama - optional)

### Required Software
- Node.js 18+ with npm
- MySQL 8.0+ or MariaDB 10.6+
- Git
- PM2 (for process management)
- Ollama (optional, for AI analysis)

## 🚀 Installation Steps

## 1. Update System Packages

### Update package lists
```sudo apt update && sudo apt upgrade -y```

### Install essential packages
```sudo apt install -y curl wget git build-essential software-properties-common```

## 2. Install Node.js 18+
### Add NodeSource repository
``curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -``

### Install Node.js and npm
``sudo apt install -y nodejs``

### Verify installation
``node --version``  # Should show v18.x.x or higher
``npm --version``   # Should show 9.x.x or higher

## 3. Install MySQL Server
### Install MySQL server
``sudo apt install -y mysql-server``

### Secure MySQL installation
``sudo mysql_secure_installation``

### Start and enable MySQL service
``sudo systemctl start mysql``
``sudo systemctl enable mysql``

## 4. Install PM2 Process Manager
### Install PM2 globally
``sudo npm install -g pm2``

### Set up PM2 to start on boot
``pm2 startup``
``sudo env PATH=$PATH:/usr/bin /usr/lib/node_modules/pm2/bin/pm2 startup systemd -u $USER --hp $HOME``

## 5. Install Ollama (Optional - for AI Analysis)
### Install Ollama
``curl -fsSL https://ollama.ai/install.sh | sh``

### Start Ollama service
``sudo systemctl start ollama``
``sudo systemctl enable ollama``

### Pull the deepseek-v2 model
``ollama pull deepseek-v2``

# 💾 Database Setup

## 1. Create Database and User
### Connect to MySQL as root
``sudo mysql -u root -p``

## Create database and user
```CREATE DATABASE security_bot;
CREATE USER 'security_bot'@'localhost' IDENTIFIED BY 'your_secure_password';
GRANT ALL PRIVILEGES ON security_bot.* TO 'security_bot'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```
## 2. Test Database Connection
### Test connection with new user
``mysql -u security_bot -p security_bot``
## Enter password when prompted
## If successful, you'll see MySQL prompt
``EXIT;``

# 📁 Bot Installation
## 1. Clone or Create Project
### Create project directory
```mkdir /opt/security-bot
cd /opt/security-bot
```

### If cloning from repository:
``git clone https://github.com/your-repo/security-bot.git .``

### Or create files manually (if you have the source files)

## 2. Create Project Structure
### Create necessary directories
```mkdir -p /opt/security-bot/logs
mkdir -p /opt/security-bot/backups
```

### Set proper ownership
``sudo chown -R $USER:$USER /opt/security-bot``
3. Create package.json
bashcat > package.json << 'EOF'
{
  "name": "discord-security-bot",
  "version": "1.0.0",
  "description": "Advanced Discord security bot for malicious URL detection",
  "main": "index.js",
  "type": "module",
  "scripts": {
    "start": "node index.js",
    "dev": "node --watch index.js",
    "pm2:start": "pm2 start ecosystem.config.js",
    "pm2:stop": "pm2 stop security-bot",
    "pm2:restart": "pm2 restart security-bot",
    "pm2:logs": "pm2 logs security-bot",
    "pm2:monit": "pm2 monit"
  },
  "keywords": [
    "discord",
    "bot",
    "security",
    "malware",
    "phishing",
    "virustotal"
  ],
  "author": "Your Name",
  "license": "MIT",
  "dependencies": {
    "discord.js": "^14.14.1",
    "dotenv": "^16.3.1",
    "axios": "^1.6.2",
    "mysql2": "^3.6.5"
  },
  "devDependencies": {
    "nodemon": "^3.0.2"
  },
  "engines": {
    "node": ">=18.0.0"
  }
}
EOF
4. Install Dependencies
bash# Install all required npm packages
npm install

# Verify installations
npm list
5. Create Source Files
Create the following files in /opt/security-bot/:

index.js (main bot file)
security.js (security module)
db.js (database module)
setup.js (setup system)

Copy the content from the previous code blocks into these files.
⚙️ Environment Configuration
1. Create .env File
bashcat > .env << 'EOF'
# Discord Bot Configuration
TOKEN=your_discord_bot_token_here

# VirusTotal API Configuration
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# Database Configuration
DB_HOST=localhost
DB_PORT=3306
DB_USER=security_bot
DB_PASSWORD=your_secure_password
DB_NAME=security_bot

# Ollama Configuration (Optional)
OLLAMA_HOST=http://localhost:11434

# Environment
NODE_ENV=production
EOF

# Secure the .env file
chmod 600 .env
2. Configure Environment Variables
bash# Edit .env file with your actual values
nano .env

# Required values to replace:
# - TOKEN: Your Discord bot token from Discord Developer Portal
# - VIRUSTOTAL_API_KEY: Your VirusTotal API key
# - DB_PASSWORD: The password you set for security_bot MySQL user
🤖 Bot Configuration
1. Discord Bot Setup

Create Discord Application:

Go to https://discord.com/developers/applications
Click "New Application"
Name it "Security Bot"
Go to "Bot" section
Click "Add Bot"
Copy the token to your .env file


Set Bot Permissions:

In Discord Developer Portal, go to "OAuth2" → "URL Generator"
Select "bot" scope
Select these permissions:

Read Messages/View Channels
Send Messages
Embed Links
Read Message History
Kick Members
Manage Messages




Invite Bot to Server:

Use the generated URL to invite bot to your server
Make sure you have "Manage Server" permission



2. VirusTotal API Setup

Get API Key:

Go to https://www.virustotal.com/
Create account or login
Go to your profile → API Key
Copy the key to your .env file


API Limits (Free Tier):

4 requests per minute
500 requests per day
The bot automatically handles rate limiting



3. Create PM2 Ecosystem File
bashcat > ecosystem.config.js << 'EOF'
module.exports = {
  apps: [{
    name: 'security-bot',
    script: 'index.js',
    cwd: '/opt/security-bot',
    instances: 1,
    exec_mode: 'fork',
    watch: false,
    max_memory_restart: '500M',
    env: {
      NODE_ENV: 'production'
    },
    error_file: './logs/err.log',
    out_file: './logs/out.log',
    log_file: './logs/combined.log',
    time: true,
    autorestart: true,
    max_restarts: 10,
    min_uptime: '10s'
  }]
}
EOF
🎯 Running the Bot
1. Test Run (Development)
bash# Test the bot manually first
cd /opt/security-bot
npm start

# Check for any errors
# Press Ctrl+C to stop
2. Production Run with PM2
bash# Start the bot with PM2
npm run pm2:start

# Check status
pm2 status

# View logs
pm2 logs security-bot

# Monitor in real-time
pm2 monit
3. Save PM2 Configuration
bash# Save current PM2 processes
pm2 save

# This ensures the bot starts automatically on system reboot
📊 Process Management
Common PM2 Commands
bash# Start the bot
pm2 start security-bot

# Stop the bot
pm2 stop security-bot

# Restart the bot
pm2 restart security-bot

# View logs
pm2 logs security-bot --lines 100

# Monitor resources
pm2 monit

# View detailed info
pm2 describe security-bot

# Delete process (removes from PM2)
pm2 delete security-bot
Log Management
bash# Rotate logs (prevents large log files)
pm2 install pm2-logrotate

# Configure log rotation
pm2 set pm2-logrotate:max_size 10M
pm2 set pm2-logrotate:retain 7
pm2 set pm2-logrotate:compress true

# View log files directly
tail -f /opt/security-bot/logs/combined.log
🔍 Monitoring & Maintenance
1. System Monitoring
bash# Check system resources
htop

# Check disk usage
df -h

# Check memory usage
free -h

# Monitor MySQL
sudo systemctl status mysql

# Monitor Ollama (if installed)
sudo systemctl status ollama
2. Database Maintenance
bash# Create backup script
cat > /opt/security-bot/backup.sh << 'EOF'
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/opt/security-bot/backups"
mysqldump -u security_bot -p security_bot > $BACKUP_DIR/security_bot_$DATE.sql
find $BACKUP_DIR -name "*.sql" -mtime +7 -delete
echo "Backup completed: security_bot_$DATE.sql"
EOF

# Make executable
chmod +x /opt/security-bot/backup.sh

# Add to crontab for daily backups
(crontab -l 2>/dev/null; echo "0 2 * * * /opt/security-bot/backup.sh") | crontab -
3. Update Management
bash# Create update script
cat > /opt/security-bot/update.sh << 'EOF'
#!/bin/bash
cd /opt/security-bot

# Stop the bot
pm2 stop security-bot

# Backup current version
cp -r . ../security-bot-backup-$(date +%Y%m%d)

# Pull updates (if using git)
# git pull origin main

# Update dependencies
npm install

# Restart the bot
pm2 restart security-bot

echo "Update completed successfully"
EOF

# Make executable
chmod +x /opt/security-bot/update.sh
🔧 Troubleshooting
Common Issues and Solutions
Bot Won't Start
bash# Check logs for errors
pm2 logs security-bot

# Common issues:
# 1. Invalid token - check .env file
# 2. Database connection - test MySQL connection
# 3. Missing permissions - check file ownership
# 4. Port conflicts - check if ports are available

# Test database connection
mysql -u security_bot -p security_bot

# Check file permissions
ls -la /opt/security-bot/
Database Connection Issues
bash# Check MySQL status
sudo systemctl status mysql

# Test connection
mysql -u security_bot -p

# Check MySQL logs
sudo tail -f /var/log/mysql/error.log

# Reset MySQL password if needed
sudo mysql -u root -p
ALTER USER 'security_bot'@'localhost' IDENTIFIED BY 'new_password';
FLUSH PRIVILEGES;
VirusTotal API Issues
bash# Test API key manually
curl -X GET "https://www.virustotal.com/vtapi/v2/url/report" \
  -d "apikey=YOUR_API_KEY" \
  -d "resource=google.com"

# Check rate limits in bot logs
pm2 logs security-bot | grep -i "rate limit"
Memory Issues
bash# Check memory usage
free -h

# Increase swap if needed
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile

# Add to /etc/fstab for persistence
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
Log Analysis
bash# Search for specific errors
pm2 logs security-bot | grep -i error

# Check last 100 lines
pm2 logs security-bot --lines 100

# Follow logs in real-time
pm2 logs security-bot --follow

# Save logs to file
pm2 logs security-bot --lines 1000 > bot_logs.txt
🔒 Security Considerations
1. File Permissions
bash# Set secure permissions
chmod 700 /opt/security-bot
chmod 600 /opt/security-bot/.env
chmod 644 /opt/security-bot/*.js
chmod 755 /opt/security-bot/*.sh
2. Firewall Configuration
bash# Install UFW if not installed
sudo apt install ufw

# Default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH (replace 22 with your SSH port)
sudo ufw allow 22

# Allow MySQL only from localhost (if needed)
sudo ufw allow from 127.0.0.1 to any port 3306

# Enable firewall
sudo ufw enable

# Check status
sudo ufw status
3. Regular Updates
bash# Create security update script
cat > /opt/security-bot/security-update.sh << 'EOF'
#!/bin/bash
# System updates
sudo apt update && sudo apt upgrade -y

# Node.js security updates
npm audit fix

# PM2 updates
pm2 update

echo "Security updates completed"
EOF

# Schedule weekly security updates
(crontab -l 2>/dev/null; echo "0 3 * * 0 /opt/security-bot/security-update.sh") | crontab -
4. Monitoring Setup
bash# Install fail2ban for additional security
sudo apt install fail2ban

# Configure basic protection
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
📈 Performance Optimization
1. MySQL Optimization
bash# Edit MySQL configuration
sudo nano /etc/mysql/mysql.conf.d/mysqld.cnf

# Add these lines under [mysqld]:
# innodb_buffer_pool_size = 256M
# query_cache_limit = 1M
# query_cache_size = 16M
# max_connections = 50

# Restart MySQL
sudo systemctl restart mysql
2. Node.js Optimization
bash# Set Node.js environment variables
echo 'export NODE_OPTIONS="--max-old-space-size=512"' >> ~/.bashrc
source ~/.bashrc
3. System Optimization
bash# Increase file descriptor limits
echo '* soft nofile 65535' | sudo tee -a /etc/security/limits.conf
echo '* hard nofile 65535' | sudo tee -a /etc/security/limits.conf

# Optimize network settings
echo 'net.core.somaxconn = 1024' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
🎉 Final Steps
1. Verify Installation
bash# Check all services
sudo systemctl status mysql
pm2 status
pm2 logs security-bot --lines 20

# Test bot in Discord
# - Invite bot to your server
# - Use setup commands to configure
# - Test with a known malicious URL
2. Documentation
bash# Create installation log
cat > /opt/security-bot/INSTALLATION.md << EOF
# Security Bot Installation Log

**Installation Date:** $(date)
**Server:** $(hostname)
**OS:** $(lsb_release -d | cut -f2)
**Node.js:** $(node --version)
**MySQL:** $(mysql --version)

## Configuration
- Database: security_bot
- Bot User: security_bot
- Log Location: /opt/security-bot/logs/
- Backup Location: /opt/security-bot/backups/

## Important Commands
- Start: pm2 start security-bot
- Stop: pm2 stop security-bot
- Logs: pm2 logs security-bot
- Backup: /opt/security-bot/backup.sh

## Maintenance Schedule
- Daily: Automatic backups at 2 AM
- Weekly: Security updates on Sunday 3 AM
- Monthly: Full system review

EOF
3. Success Checklist

 Bot appears online in Discord
 Database tables created successfully
 VirusTotal API working (check logs)
 PM2 process running stable
 Backup script working
 All log files being written
 Bot responds to setup commands
 Security scanning functional

📞 Support
If you encounter issues:

Check Logs: pm2 logs security-bot
Verify Configuration: Review .env file
Test Components: Database, API keys, permissions
Search Documentation: This guide covers most scenarios
System Resources: Ensure adequate RAM/disk space


Congratulations! Your Discord Security Bot is now installed and running. The bot will automatically protect your Discord server from malicious URLs, phishing attempts, and other security threats.
