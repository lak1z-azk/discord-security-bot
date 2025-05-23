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

### 1. Update System Packages

# Update package lists
```sudo apt update && sudo apt upgrade -y```

# Install essential packages
```sudo apt install -y curl wget git build-essential software-properties-common```

### 2. Install Node.js 18+
# Add NodeSource repository
``curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -``

# Install Node.js and npm
``sudo apt install -y nodejs``

# Verify installation
``node --version``  # Should show v18.x.x or higher
``npm --version``   # Should show 9.x.x or higher

# 3. Install MySQL Server
