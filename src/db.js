import mysql from 'mysql2/promise';
import { config } from 'dotenv';

config();

// Create connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  acquireTimeout: 60000,
  timeout: 60000,
  reconnect: true
});

// Database initialization
export async function initializeDatabase() {
  try {
    console.log('🔗 Connecting to database...');
    
    // Test connection
    const connection = await pool.getConnection();
    console.log(`✅ Connected to MySQL database: ${process.env.DB_NAME}`);
    connection.release();
    
    // Create all required tables
    await createTables();
    
    console.log('✅ Database initialization completed successfully');
  } catch (error) {
    console.error('❌ Database initialization failed:', error);
    throw error;
  }
}

// Create all necessary tables
async function createTables() {
  try {
    // Blocklist table for malicious domains
    const createBlockedListTable = `
      CREATE TABLE IF NOT EXISTS blockedList (
        id INT AUTO_INCREMENT PRIMARY KEY,
        list VARCHAR(255) NOT NULL UNIQUE,
        added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        added_by VARCHAR(255) DEFAULT 'system',
        threat_type VARCHAR(100) DEFAULT 'malicious',
        notes TEXT,
        INDEX idx_list (list),
        INDEX idx_added_date (added_date)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `;
    
    // Blocked messages log table
    const createBlockedMessagesTable = `
      CREATE TABLE IF NOT EXISTS blockedMessages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        userID VARCHAR(255) NOT NULL,
        userName VARCHAR(255) NOT NULL,
        content TEXT NOT NULL,
        orgChannelID VARCHAR(255) NOT NULL,
        guildID VARCHAR(255),
        threat_data JSON,
        detected_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        action_taken VARCHAR(100) DEFAULT 'kicked',
        INDEX idx_user (userID),
        INDEX idx_guild (guildID),
        INDEX idx_date (detected_date),
        INDEX idx_action (action_taken)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `;

    // URL scan cache table
    const createUrlCacheTable = `
      CREATE TABLE IF NOT EXISTS url_scan_cache (
        url VARCHAR(500) PRIMARY KEY,
        scan_result JSON NOT NULL,
        scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP DEFAULT (DATE_ADD(CURRENT_TIMESTAMP, INTERVAL 24 HOUR)),
        INDEX idx_scan_date (scan_date),
        INDEX idx_expires (expires_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `;

    // Server configuration table
    const createServerConfigTable = `
      CREATE TABLE IF NOT EXISTS server_config (
        guild_id VARCHAR(255) PRIMARY KEY,
        log_channel_id VARCHAR(255),
        admin_role_ids JSON,
        immune_role_ids JSON,
        auto_kick BOOLEAN DEFAULT TRUE,
        auto_delete_messages BOOLEAN DEFAULT TRUE,
        scan_enabled BOOLEAN DEFAULT TRUE,
        setup_completed BOOLEAN DEFAULT FALSE,
        setup_date TIMESTAMP NULL,
        setup_by VARCHAR(255),
        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_setup_completed (setup_completed),
        INDEX idx_scan_enabled (scan_enabled)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `;

    // Bot statistics table
    const createStatsTable = `
      CREATE TABLE IF NOT EXISTS bot_stats (
        id INT AUTO_INCREMENT PRIMARY KEY,
        date DATE NOT NULL UNIQUE,
        messages_scanned INT DEFAULT 0,
        threats_detected INT DEFAULT 0,
        urls_scanned INT DEFAULT 0,
        users_kicked INT DEFAULT 0,
        servers_active INT DEFAULT 0,
        virustotal_requests INT DEFAULT 0,
        cache_hits INT DEFAULT 0,
        cache_misses INT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_date (date)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `;

    // Security events table for detailed logging
    const createSecurityEventsTable = `
      CREATE TABLE IF NOT EXISTS security_events (
        id INT AUTO_INCREMENT PRIMARY KEY,
        event_type VARCHAR(50) NOT NULL,
        guild_id VARCHAR(255),
        user_id VARCHAR(255),
        channel_id VARCHAR(255),
        event_data JSON,
        severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') DEFAULT 'MEDIUM',
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_event_type (event_type),
        INDEX idx_guild (guild_id),
        INDEX idx_severity (severity),
        INDEX idx_timestamp (timestamp)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `;

    // User warnings table
    const createUserWarningsTable = `
      CREATE TABLE IF NOT EXISTS user_warnings (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id VARCHAR(255) NOT NULL,
        guild_id VARCHAR(255) NOT NULL,
        warning_type VARCHAR(100) NOT NULL,
        reason TEXT,
        issued_by VARCHAR(255),
        issued_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_date TIMESTAMP NULL,
        active BOOLEAN DEFAULT TRUE,
        INDEX idx_user_guild (user_id, guild_id),
        INDEX idx_active (active),
        INDEX idx_expires (expires_date)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `;

    // Execute table creation
    await pool.query(createBlockedListTable);
    console.log('✅ Created/verified blockedList table');
    
    await pool.query(createBlockedMessagesTable);
    console.log('✅ Created/verified blockedMessages table');
    
    await pool.query(createUrlCacheTable);
    console.log('✅ Created/verified url_scan_cache table');
    
    await pool.query(createServerConfigTable);
    console.log('✅ Created/verified server_config table');
    
    await pool.query(createStatsTable);
    console.log('✅ Created/verified bot_stats table');
    
    await pool.query(createSecurityEventsTable);
    console.log('✅ Created/verified security_events table');
    
    await pool.query(createUserWarningsTable);
    console.log('✅ Created/verified user_warnings table');

    // Add some initial data if tables are empty
    await initializeDefaultData();
    
    console.log('🗄️ All database tables created/verified successfully');
  } catch (error) {
    console.error('❌ Error creating database tables:', error);
    throw error;
  }
}

// Initialize default data
async function initializeDefaultData() {
  try {
    // Add today's stats entry if it doesn't exist
    const today = new Date().toISOString().split('T')[0];
    await pool.query(
      'INSERT IGNORE INTO bot_stats (date) VALUES (?)',
      [today]
    );

    // Add some common malicious domains to blocklist if empty
    const [existingCount] = await pool.query('SELECT COUNT(*) as count FROM blockedList');
    
    if (existingCount[0].count === 0) {
      const maliciousDomains = [
        'example-phishing.com',
        'fake-bank-login.net',
        'malware-download.org',
        'suspicious-site.xyz'
      ];

      for (const domain of maliciousDomains) {
        await pool.query(
          'INSERT IGNORE INTO blockedList (list, added_by, threat_type, notes) VALUES (?, ?, ?, ?)',
          [domain, 'system', 'example', 'Initial example malicious domain']
        );
      }
      
      console.log(`✅ Added ${maliciousDomains.length} example malicious domains to blocklist`);
    }
  } catch (error) {
    console.error('❌ Error initializing default data:', error);
  }
}

// Database utility functions

// Get server configuration
export async function getServerConfig(guildId) {
  try {
    const [rows] = await pool.query(
      'SELECT * FROM server_config WHERE guild_id = ?',
      [guildId]
    );
    return rows[0] || null;
  } catch (error) {
    console.error('❌ Error fetching server config:', error);
    return null;
  }
}

// Update server configuration
export async function updateServerConfig(guildId, config) {
  try {
    const [result] = await pool.query(
      `INSERT INTO server_config 
       (guild_id, log_channel_id, admin_role_ids, immune_role_ids, auto_kick, auto_delete_messages, scan_enabled, setup_completed, setup_by) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE 
       log_channel_id = VALUES(log_channel_id),
       admin_role_ids = VALUES(admin_role_ids),
       immune_role_ids = VALUES(immune_role_ids),
       auto_kick = VALUES(auto_kick),
       auto_delete_messages = VALUES(auto_delete_messages),
       scan_enabled = VALUES(scan_enabled),
       setup_completed = VALUES(setup_completed),
       setup_by = VALUES(setup_by)`,
      [
        guildId,
        config.log_channel_id || null,
        JSON.stringify(config.admin_role_ids || []),
        JSON.stringify(config.immune_role_ids || []),
        config.auto_kick !== undefined ? config.auto_kick : true,
        config.auto_delete_messages !== undefined ? config.auto_delete_messages : true,
        config.scan_enabled !== undefined ? config.scan_enabled : true,
        config.setup_completed !== undefined ? config.setup_completed : false,
        config.setup_by || null
      ]
    );
    return result.affectedRows > 0;
  } catch (error) {
    console.error('❌ Error updating server config:', error);
    return false;
  }
}

// Log security events
export async function logSecurityEvent(eventType, guildId, userId, channelId, eventData, severity = 'MEDIUM') {
  try {
    await pool.query(
      'INSERT INTO security_events (event_type, guild_id, user_id, channel_id, event_data, severity) VALUES (?, ?, ?, ?, ?, ?)',
      [eventType, guildId, userId, channelId, JSON.stringify(eventData), severity]
    );
  } catch (error) {
    console.error('❌ Error logging security event:', error);
  }
}

// Update daily statistics
export async function updateDailyStats(field, increment = 1) {
  try {
    const today = new Date().toISOString().split('T')[0];
    await pool.query(
      `INSERT INTO bot_stats (date, ${field}) VALUES (?, ?) 
       ON DUPLICATE KEY UPDATE ${field} = ${field} + ?`,
      [today, increment, increment]
    );
  } catch (error) {
    console.error('❌ Error updating daily stats:', error);
  }
}

// Get daily statistics
export async function getDailyStats(days = 7) {
  try {
    const [rows] = await pool.query(
      'SELECT * FROM bot_stats WHERE date >= DATE_SUB(CURDATE(), INTERVAL ? DAY) ORDER BY date DESC',
      [days]
    );
    return rows;
  } catch (error) {
    console.error('❌ Error fetching daily stats:', error);
    return [];
  }
}

// Get top threats
export async function getTopThreats(limit = 10) {
  try {
    const [rows] = await pool.query(
      'SELECT list, added_date, threat_type, COUNT(*) as detections FROM blockedList bl LEFT JOIN blockedMessages bm ON bl.list LIKE CONCAT("%", SUBSTRING_INDEX(SUBSTRING_INDEX(bm.content, "://", -1), "/", 1), "%") GROUP BY bl.id ORDER BY detections DESC, added_date DESC LIMIT ?',
      [limit]
    );
    return rows;
  } catch (error) {
    console.error('❌ Error fetching top threats:', error);
    return [];
  }
}

// Clean up old data
export async function cleanupOldData() {
  try {
    // Clean old cache entries
    await pool.query(
      'DELETE FROM url_scan_cache WHERE expires_at < NOW()'
    );

    // Clean old security events (older than 30 days)
    await pool.query(
      'DELETE FROM security_events WHERE timestamp < DATE_SUB(NOW(), INTERVAL 30 DAY)'
    );

    // Clean expired warnings
    await pool.query(
      'UPDATE user_warnings SET active = FALSE WHERE expires_date < NOW() AND active = TRUE'
    );

    console.log('✅ Completed database cleanup');
  } catch (error) {
    console.error('❌ Error during database cleanup:', error);
  }
}

// Database health check
export async function checkDatabaseHealth() {
  try {
    const connection = await pool.getConnection();
    await connection.ping();
    connection.release();
    return { healthy: true, message: 'Database connection is healthy' };
  } catch (error) {
    console.error('❌ Database health check failed:', error);
    return { healthy: false, message: error.message };
  }
}

// Export the pool for use in other modules
export { pool };

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('🔄 Closing database connections...');
  await pool.end();
});

process.on('SIGTERM', async () => {
  console.log('🔄 Closing database connections...');
  await pool.end();
});
