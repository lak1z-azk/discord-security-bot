# Discord Security Bot

An advanced Discord security bot that automatically scans URLs for malicious content, protects servers from threats, and provides comprehensive security monitoring.

## 🌟 Features

- **Real-time URL Scanning**: Automatically scans all URLs posted in your server
- **VirusTotal Integration**: Uses VirusTotal API for comprehensive threat detection
- **AI-Powered Analysis**: Provides intelligent threat analysis using Ollama AI
- **Automated Protection**: Automatically kicks users and deletes malicious content
- **Smart Caching**: Reduces API calls with intelligent result caching
- **Comprehensive Logging**: Detailed security event logging and statistics
- **Easy Setup**: Interactive setup wizard for quick configuration
- **Role-Based Permissions**: Configurable admin and immune roles
- **Database Persistence**: MySQL database for reliable data storage

## 🚀 Quick Start

### Prerequisites

- Node.js 18.0.0 or higher
- MySQL 8.0 or higher
- Discord Bot Token
- VirusTotal API Key (optional but recommended)
- Ollama Server (optional, for AI analysis)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/discord-security-bot.git
   cd discord-security-bot
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Configure environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Set up the database**
   ```bash
   # Create your MySQL database first, then run:
   npm run db:setup
   ```

5. **Start the bot**
   ```bash
   npm start
   ```

## ⚙️ Configuration

### Environment Variables

Create a `.env` file in the root directory with the following variables:

```env
# Required
DISCORD_TOKEN=your_discord_bot_token_here
DB_HOST=localhost
DB_PORT=3306
DB_USER=your_database_username
DB_PASSWORD=your_database_password
DB_NAME=security_bot_db

# Optional but recommended
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
OLLAMA_SERVER_URL=http://localhost:11434/api
STARTUP_LOG_CHANNEL=your_startup_log_channel_id
```

### Discord Bot Setup

1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Create a new application and bot
3. Copy the bot token and add it to your `.env` file
4. Enable the following bot permissions:
   - Send Messages
   - Embed Links
   - Read Message History
   - Manage Messages
   - Kick Members
   - View Channels
5. Enable the following privileged gateway intents:
   - Server Members Intent
   - Message Content Intent
6. Invite the bot to your server with the required permissions

### Database Setup

The bot requires a MySQL database. Create the database and update your `.env` file:

```sql
CREATE DATABASE security_bot_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'security_bot'@'localhost' IDENTIFIED BY 'your_secure_password';
GRANT ALL PRIVILEGES ON security_bot_db.* TO 'security_bot'@'localhost';
FLUSH PRIVILEGES;
```

## 📊 Database Schema

The bot automatically creates the following tables:

- **`blockedList`** - Stores malicious domains and URLs
- **`blockedMessages`** - Logs blocked messages and user actions
- **`url_scan_cache`** - Caches scan results to reduce API usage
- **`server_config`** - Stores per-server configuration settings
- **`bot_stats`** - Daily statistics and metrics
- **`security_events`** - Detailed security event logging
- **`user_warnings`** - User warning system

## 🎛️ Bot Commands

The bot primarily works automatically, but includes these management features:

### Setup Commands
- **Interactive Setup**: When added to a server, the bot sends a DM with setup instructions
- **Setup Wizard**: Click the setup button to configure the bot for your server

### Admin Features
- Real-time threat monitoring
- Configurable security actions
- Role-based permissions
- Comprehensive logging

## 🔧 Configuration Options

### Security Settings

- **Auto-kick**: Automatically kick users who post malicious URLs
- **Auto-delete**: Delete messages containing malicious content
- **URL Scanning**: Enable/disable URL scanning (not recommended to disable)

### Role Configuration

- **Admin Roles**: Roles that can manage bot settings
- **Immune Roles**: Roles that bypass all security scanning (use carefully)

### Logging

- **Log Channel**: Channel where security events are logged
- **Event Types**: Malicious URL detections, user actions, bot status

## 🛡️ Security Features

### URL Scanning Process

1. **Real-time Detection**: All messages are scanned for URLs
2. **Cache Check**: First checks local cache for known results
3. **Blocklist Check**: Compares against known malicious domains
4. **VirusTotal Scan**: Uses VirusTotal API for comprehensive analysis
5. **AI Analysis**: Optional AI-powered threat assessment
6. **Action Execution**: Automatic response based on configuration

### Threat Detection

- **Multiple Engines**: VirusTotal uses 70+ antivirus engines
- **Threat Categories**: Phishing, malware, trojans, suspicious sites
- **False Positive Handling**: Smart thresholds to minimize false positives
- **Rate Limiting**: Respects API limits with intelligent queuing

### Automated Response

When a malicious URL is detected:
1. Message is immediately deleted
2. User is kicked from the server
3. Recent messages from user are cleaned up
4. Domain is added to blocklist
5. Security event is logged
6. Admin notifications are sent

## 📈 Monitoring & Statistics

### Real-time Status

The bot displays live statistics in its status:
- Number of servers protected
- Threats blocked today
- Messages scanned
- Current uptime
- Cache performance

### Daily Reports

Automatic generation of:
- Threat detection summaries
- Server protection statistics
- API usage metrics
- Performance analytics

## 🔒 Security Considerations

### Privacy

- Only URLs are analyzed, not message content
- No personal data is stored beyond Discord IDs
- Scan results are cached temporarily for performance
- Logs can be automatically purged after configured time

### Performance

- Intelligent caching reduces API calls
- Rate limiting prevents API quota exhaustion
- Async processing prevents bot delays
- Database optimization for high-volume servers

### Reliability

- Graceful error handling
- Automatic reconnection to database
- Fallback modes if external services are unavailable
- Comprehensive logging for debugging

## 🚨 Troubleshooting

### Common Issues

**Bot not responding to URLs:**
- Check if URL scanning is enabled in server config
- Verify bot has necessary permissions
- Check VirusTotal API key validity

**Database connection errors:**
- Verify database credentials in `.env`
- Ensure MySQL server is running
- Check database user permissions

**Setup wizard not working:**
- Ensure bot has permission to send DMs
- Check if user has Administrator permission
- Verify bot is properly added to server

### Error Codes

- `VT_RATE_LIMITED`: VirusTotal API rate limit exceeded
- `DB_CONNECTION_FAILED`: Database connection issue
- `INSUFFICIENT_PERMISSIONS`: Bot lacks required permissions
- `SETUP_INCOMPLETE`: Server setup not completed

## 📝 API Integration

### VirusTotal API

The bot integrates with VirusTotal for comprehensive URL scanning:
- **Free Tier**: 4 requests/minute, 500 requests/day
- **Premium Tier**: Higher limits available
- **Fallback**: Works without API key but with reduced functionality

### Ollama AI Integration

Optional AI analysis for enhanced threat detection:
- Local AI server for privacy
- Contextual threat analysis
- Natural language threat descriptions
- Configurable AI models

## 🔄 Updates & Maintenance

### Automatic Maintenance

The bot performs automatic maintenance:
- Cache cleanup every hour
- Database optimization daily
- Log rotation based on retention settings
- Performance statistics collection

### Manual Maintenance

Recommended periodic tasks:
- Review and update blocklist
- Monitor API usage and costs
- Check server configurations
- Update bot permissions as needed

## 🤝 Contributing

We welcome contributions! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/discord-security-bot.git
cd discord-security-bot

# Install dependencies
npm install

# Set up development environment
cp .env.example .env.dev
# Configure .env.dev for development

# Run in development mode
npm run dev
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

Need help? Here's how to get support:

1. **Documentation**: Check this README and code comments
2. **Issues**: Create a GitHub issue for bugs or feature requests
3. **Discussions**: Use GitHub Discussions for questions
4. **Discord**: Join our support server (link in repository)

## 🙏 Acknowledgments

- **Discord.js**: Excellent Discord API library
- **VirusTotal**: Comprehensive threat intelligence
- **MySQL**: Reliable database system
- **Ollama**: Local AI integration
- **Community**: Contributors and users who make this project better

---

**⚠️ Important Security Notice**: This bot automatically kicks users and deletes messages when malicious content is detected. Ensure proper configuration and testing before deploying in production environments.
