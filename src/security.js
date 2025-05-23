import axios from "axios";
import { EmbedBuilder } from 'discord.js';
import { config } from 'dotenv';
import { pool, getServerConfig, logSecurityEvent, updateDailyStats } from './db.js';

config();

// We'll pass the updateThreatCounter function from index.js to avoid circular imports
let updateThreatCounterCallback = null;

export function setUpdateThreatCounter(callback) {
  updateThreatCounterCallback = callback;
}

config();

const OLLAMA_SERVER_URL = process.env.OLLAMA_SERVER_URL || "http://localhost:11434/api";
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const VIRUSTOTAL_API_URL = "https://www.virustotal.com/vtapi/v2/url";

// Rate limiting and caching
const urlScanCache = new Map(); // Cache scan results
const scanQueue = new Set(); // Track URLs currently being scanned
const rateLimiter = {
  requests: [],
  maxRequests: parseInt(process.env.VT_RATE_LIMIT) || 4, // VirusTotal free tier: 4 requests per minute
  timeWindow: 60000, // 1 minute
  dailyRequests: 0,
  maxDailyRequests: parseInt(process.env.VT_DAILY_LIMIT) || 500, // Daily limit
  lastResetDate: new Date().toDateString()
};

// Cache configuration
const CACHE_DURATION = (parseInt(process.env.CACHE_DURATION_HOURS) || 24) * 60 * 60 * 1000; // 24 hours default
const MAX_CACHE_SIZE = parseInt(process.env.MAX_CACHE_SIZE) || 1000;

export async function initializeSecurity(client) {
  console.log('🔒 Initializing security module...');
  
  try {
    await loadCacheFromDatabase();
    
    // Clean cache periodically
    setInterval(cleanCache, 60 * 60 * 1000); // Every hour
    
    console.log('✅ Security cache loaded successfully');
  } catch (error) {
    console.error('❌ Error loading security cache:', error);
    return;
  }

  client.on('messageCreate', async (message) => {
    // Skip bot messages, DMs
    if (message.author.bot || !message.guild || !message.member) {
      return;
    }

    try {
      // Get server configuration
      const serverConfig = await getServerConfig(message.guild.id);
      
      // Skip if scanning is disabled for this server
      if (serverConfig && !serverConfig.scan_enabled) {
        return;
      }

      // Check if user has immune role
      if (serverConfig?.immune_role_ids && Array.isArray(serverConfig.immune_role_ids)) {
        const hasImmuneRole = serverConfig.immune_role_ids.some(roleId => 
          message.member.roles.cache.has(roleId)
        );
        if (hasImmuneRole) {
          return;
        }
      }

      // Extract URLs from message
      const urls = extractUrls(message.content);
      if (urls.length === 0) {
        return; // No URLs to check
      }

      console.log(`🔍 Found ${urls.length} URL(s) in message from ${message.author.tag}`);
      await updateDailyStats('messages_scanned', 1);

      // Check each unique URL
      const uniqueUrls = [...new Set(urls)]; // Remove duplicates
      
      for (const url of uniqueUrls) {
        await updateDailyStats('urls_scanned', 1);
        const threatData = await checkUrl(url, message);
        if (threatData.isMalicious) {
          console.log(`🚨 Malicious URL detected: ${url}`);
          
          // Update statistics
          await updateDailyStats('threats_detected', 1);
          if (updateThreatCounterCallback) {
            updateThreatCounterCallback(); // Update bot status counter
          }
          
          // Take action immediately and return
          await handleMaliciousUrl(message, url, threatData, serverConfig);
          return;
        }
      }

      console.log('✅ All URLs checked - no threats detected');
    } catch (error) {
      console.error('❌ Error processing message in security module:', error);
    }
  });

  console.log('✅ Security module initialized successfully');
}

// Rate limiting functions
function canMakeRequest() {
  const now = Date.now();
  const currentDate = new Date().toDateString();
  
  // Reset daily counter if new day
  if (rateLimiter.lastResetDate !== currentDate) {
    rateLimiter.dailyRequests = 0;
    rateLimiter.lastResetDate = currentDate;
  }
  
  // Check daily limit
  if (rateLimiter.dailyRequests >= rateLimiter.maxDailyRequests) {
    console.warn('⚠️ VirusTotal daily request limit reached');
    return false;
  }
  
  // Clean old requests from rate limiter
  rateLimiter.requests = rateLimiter.requests.filter(time => now - time < rateLimiter.timeWindow);
  
  // Check rate limit
  if (rateLimiter.requests.length >= rateLimiter.maxRequests) {
    console.warn('⚠️ VirusTotal rate limit reached, waiting...');
    return false;
  }
  
  return true;
}

function recordRequest() {
  rateLimiter.requests.push(Date.now());
  rateLimiter.dailyRequests++;
  updateDailyStats('virustotal_requests', 1);
}

// Load cache from database and also load known malicious domains
async function loadCacheFromDatabase() {
  try {
    // Load recent URL scan cache
    const [cacheRows] = await pool.query(
      'SELECT url, scan_result, scan_date FROM url_scan_cache WHERE expires_at > NOW()'
    );
    
    for (const row of cacheRows) {
      urlScanCache.set(row.url, {
        result: JSON.parse(row.scan_result),
        timestamp: new Date(row.scan_date).getTime()
      });
    }
    
    console.log(`📦 Loaded ${cacheRows.length} cached scan results from database`);
    
    // Also pre-load blocklisted domains into cache as malicious
    const [blocklistRows] = await pool.query('SELECT list, added_date FROM blockedList');
    
    let preloadedCount = 0;
    for (const row of blocklistRows) {
      const domain = row.list;
      // Create cache entries for known malicious domains
      const maliciousResult = {
        isMalicious: true,
        source: 'local_blocklist',
        details: {
          reason: 'Previously identified as malicious',
          added_date: row.added_date,
          preloaded: true
        }
      };
      
      // Cache both http and https versions
      const httpUrl = `http://${domain}`;
      const httpsUrl = `https://${domain}`;
      
      urlScanCache.set(httpUrl, { result: maliciousResult, timestamp: Date.now() });
      urlScanCache.set(httpsUrl, { result: maliciousResult, timestamp: Date.now() });
      preloadedCount += 2;
    }
    
    console.log(`🛡️ Pre-loaded ${preloadedCount} blocklisted domains into cache`);
    console.log(`📊 Total cache size: ${urlScanCache.size} entries`);
    
  } catch (error) {
    console.error('❌ Error loading cache from database:', error);
  }
}

async function saveCacheToDatabase(url, result) {
  try {
    await pool.query(
      'INSERT INTO url_scan_cache (url, scan_result, scan_date, expires_at) VALUES (?, ?, NOW(), DATE_ADD(NOW(), INTERVAL ? HOUR)) ON DUPLICATE KEY UPDATE scan_result = VALUES(scan_result), scan_date = VALUES(scan_date), expires_at = VALUES(expires_at)',
      [url, JSON.stringify(result), parseInt(process.env.CACHE_DURATION_HOURS) || 24]
    );
  } catch (error) {
    console.error('❌ Error saving cache to database:', error);
  }
}

function cleanCache() {
  const now = Date.now();
  let cleaned = 0;
  
  for (const [url, data] of urlScanCache.entries()) {
    if (now - data.timestamp > CACHE_DURATION) {
      urlScanCache.delete(url);
      cleaned++;
    }
  }
  
  // If cache is too large, remove oldest entries
  if (urlScanCache.size > MAX_CACHE_SIZE) {
    const entries = Array.from(urlScanCache.entries())
      .sort((a, b) => a[1].timestamp - b[1].timestamp);
    
    const toRemove = urlScanCache.size - MAX_CACHE_SIZE;
    for (let i = 0; i < toRemove; i++) {
      urlScanCache.delete(entries[i][0]);
      cleaned++;
    }
  }
  
  if (cleaned > 0) {
    console.log(`🧹 Cleaned ${cleaned} entries from URL scan cache`);
  }
}

// Extract URLs from message content
function extractUrls(content) {
  const urlRegex = /https?:\/\/[^\s]+/gi;
  return content.match(urlRegex) || [];
}

// Main URL checking function
async function checkUrl(url, message) {
  try {
    const normalizedUrl = normalizeUrl(url);
    
    // Step 1: Check cache first
    const cached = urlScanCache.get(normalizedUrl);
    if (cached && (Date.now() - cached.timestamp) < CACHE_DURATION) {
      console.log(`💾 Using cached result for: ${normalizedUrl}`);
      await updateDailyStats('cache_hits', 1);
      return cached.result;
    }
    
    await updateDailyStats('cache_misses', 1);
    
    // Step 2: Check if already being scanned
    if (scanQueue.has(normalizedUrl)) {
      console.log(`⏳ URL already being scanned: ${normalizedUrl}`);
      return { isMalicious: false, reason: 'scan_in_progress' };
    }
    
    // Step 3: Check against local blocklist
    const blocklistResult = await checkAgainstBlocklist(normalizedUrl);
    if (blocklistResult.isBlocked) {
      console.log(`🚫 URL found in local blocklist: ${normalizedUrl}`);
      const result = { 
        isMalicious: true, 
        source: 'local_blocklist',
        details: { 
          reason: 'Previously identified as malicious',
          added_date: blocklistResult.added_date 
        }
      };
      urlScanCache.set(normalizedUrl, { result, timestamp: Date.now() });
      return result;
    }

    // Step 4: Scan with VirusTotal if rate limits allow
    console.log(`🔍 Scanning with VirusTotal: ${normalizedUrl}`);
    scanQueue.add(normalizedUrl);
    
    try {
      const virusTotalResult = await scanWithVirusTotal(normalizedUrl);
      
      if (virusTotalResult.isMalicious) {
        console.log(`🚨 VirusTotal detected malicious URL: ${normalizedUrl}`);
        
        // Add to blocklist immediately - this is crucial!
        console.log(`🔒 Adding malicious domain to blocklist...`);
        const addedToBlocklist = await addToBlocklist(normalizedUrl);
        
        if (addedToBlocklist) {
          console.log(`✅ Successfully added domain to blocklist: ${extractDomain(normalizedUrl)}`);
        } else {
          console.log(`ℹ️  Domain was already in blocklist: ${extractDomain(normalizedUrl)}`);
        }
        
        // Cache the result
        urlScanCache.set(normalizedUrl, { result: virusTotalResult, timestamp: Date.now() });
        await saveCacheToDatabase(normalizedUrl, virusTotalResult);
        
        return virusTotalResult;
      } else {
        console.log(`✅ VirusTotal scan clean: ${normalizedUrl}`);
      }
      
      // Cache clean results too
      urlScanCache.set(normalizedUrl, { result: virusTotalResult, timestamp: Date.now() });
      await saveCacheToDatabase(normalizedUrl, virusTotalResult);
      
      return virusTotalResult;
    } finally {
      scanQueue.delete(normalizedUrl);
    }

  } catch (error) {
    console.error('❌ Error checking URL:', error);
    scanQueue.delete(normalizeUrl(url));
    return { isMalicious: false, error: error.message };
  }
}

// Normalize URL for consistent caching
function normalizeUrl(url) {
  try {
    const urlObj = new URL(url);
    // Remove common tracking parameters
    const trackingParams = ['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'fbclid', 'gclid'];
    trackingParams.forEach(param => urlObj.searchParams.delete(param));
    
    return urlObj.toString().toLowerCase();
  } catch (error) {
    return url.toLowerCase();
  }
}

// Check URL against local blocklist with detailed info
async function checkAgainstBlocklist(url) {
  try {
    const domain = extractDomain(url);
    const [rows] = await pool.query(
      'SELECT id, added_date FROM blockedList WHERE list = ? LIMIT 1', 
      [domain]
    );
    
    if (rows.length > 0) {
      return {
        isBlocked: true,
        id: rows[0].id,
        added_date: rows[0].added_date
      };
    }
    
    return { isBlocked: false };
  } catch (error) {
    console.error('❌ Error checking against blocklist:', error);
    return { isBlocked: false };
  }
}

// Extract domain from URL with better debugging
function extractDomain(url) {
  try {
    console.log(`🔍 Extracting domain from: ${url}`);
    const urlObj = new URL(url);
    const domain = urlObj.hostname.replace(/^www\./, '');
    console.log(`📌 Extracted domain: ${domain}`);
    return domain;
  } catch (error) {
    console.error('❌ Error extracting domain from URL:', error);
    console.error('URL that failed:', url);
    // Fallback: try to extract domain manually
    try {
      const cleanUrl = url.replace(/^https?:\/\//i, '').split('/')[0].replace(/^www\./, '');
      console.log(`🔧 Fallback extraction result: ${cleanUrl}`);
      return cleanUrl;
    } catch (fallbackError) {
      console.error('❌ Fallback extraction also failed:', fallbackError);
      return url;
    }
  }
}

// Scan URL with VirusTotal
async function scanWithVirusTotal(url) {
  if (!VIRUSTOTAL_API_KEY) {
    console.warn('⚠️ VirusTotal API key not found - skipping VirusTotal scan');
    return { isMalicious: false, source: 'no_api_key', details: 'API key not configured' };
  }

  if (!canMakeRequest()) {
    console.warn('⚠️ VirusTotal rate limit reached - skipping scan');
    return { isMalicious: false, source: 'rate_limited', details: 'Rate limit exceeded' };
  }

  try {
    console.log(`🔍 Scanning URL with VirusTotal: ${url}`);
    recordRequest();

    // First, try to get existing report
    const reportResponse = await axios.get(`${VIRUSTOTAL_API_URL}/report`, {
      params: {
        apikey: VIRUSTOTAL_API_KEY,
        resource: url
      }
    });

    let report = reportResponse.data;
    
    // If no report exists, submit for scanning
    if (report.response_code !== 1) {
      console.log('📝 No existing report, submitting URL for scanning...');
      
      if (!canMakeRequest()) {
        return { isMalicious: false, source: 'rate_limited', details: 'Rate limit exceeded during submission' };
      }
      
      recordRequest();
      
      const scanResponse = await axios.post(`${VIRUSTOTAL_API_URL}/scan`, null, {
        params: {
          apikey: VIRUSTOTAL_API_KEY,
          url: url
        }
      });

      if (scanResponse.data.response_code !== 1) {
        console.warn('⚠️ VirusTotal scan submission failed:', scanResponse.data);
        return { isMalicious: false, source: 'scan_failed', details: 'Scan submission failed' };
      }

      // Wait for scan to complete (with timeout)
      let attempts = 0;
      const maxAttempts = 3;
      
      while (attempts < maxAttempts) {
        await new Promise(resolve => setTimeout(resolve, 15000)); // Wait 15 seconds
        
        if (!canMakeRequest()) {
          return { isMalicious: false, source: 'rate_limited', details: 'Rate limit exceeded during report retrieval' };
        }
        
        recordRequest();
        
        const newReportResponse = await axios.get(`${VIRUSTOTAL_API_URL}/report`, {
          params: {
            apikey: VIRUSTOTAL_API_KEY,
            resource: url
          }
        });
        
        if (newReportResponse.data.response_code === 1) {
          report = newReportResponse.data;
          break;
        }
        
        attempts++;
      }
      
      if (report.response_code !== 1) {
        console.log('⏳ VirusTotal scan still pending after maximum attempts');
        return { isMalicious: false, source: 'scan_pending', details: 'Scan still in progress' };
      }
    }

    // Analyze the results
    const positives = report.positives || 0;
    const total = report.total || 0;
    
    console.log(`📊 VirusTotal results: ${positives}/${total} engines detected threats`);

    // Consider malicious if 2 or more engines detect it, or if specifically flagged as phishing/malware
    const isMalicious = positives >= 2;
    
    // Get detailed analysis of detected threats
    const threatCategories = [];
    const detectionEngines = [];
    
    if (report.scans) {
      for (const [engine, result] of Object.entries(report.scans)) {
        if (result.detected) {
          detectionEngines.push({
            engine: engine,
            result: result.result
          });
          
          // Categorize threats
          const resultLower = result.result.toLowerCase();
          if (resultLower.includes('phishing')) threatCategories.push('Phishing');
          if (resultLower.includes('malware')) threatCategories.push('Malware');
          if (resultLower.includes('trojan')) threatCategories.push('Trojan');
          if (resultLower.includes('spam')) threatCategories.push('Spam');
          if (resultLower.includes('suspicious')) threatCategories.push('Suspicious');
        }
      }
    }

    return {
      isMalicious,
      source: 'virustotal',
      details: {
        positives,
        total,
        scan_date: report.scan_date,
        permalink: report.permalink,
        threat_categories: [...new Set(threatCategories)],
        detection_engines: detectionEngines.slice(0, 5), // Limit to top 5 detections
        scan_id: report.scan_id
      }
    };

  } catch (error) {
    console.error('❌ Error scanning with VirusTotal:', error);
    return { isMalicious: false, source: 'error', details: `Scan error: ${error.message}` };
  }
}

// Add URL domain to blocklist with better error handling and debugging
async function addToBlocklist(url) {
  try {
    const domain = extractDomain(url);
    console.log(`🔍 Attempting to add domain to blocklist: ${domain} (from URL: ${url})`);
    
    // Check if already exists first
    const [existing] = await pool.query('SELECT id FROM blockedList WHERE list = ? LIMIT 1', [domain]);
    
    if (existing.length === 0) {
      console.log(`📝 Domain not found in blocklist, adding: ${domain}`);
      const [result] = await pool.query(
        'INSERT INTO blockedList (list, added_by, threat_type, notes) VALUES (?, ?, ?, ?)', 
        [domain, 'system', 'malicious', 'Auto-detected by VirusTotal']
      );
      console.log(`✅ Successfully added domain to blocklist: ${domain} (ID: ${result.insertId})`);
      
      // Verify it was added
      const [verify] = await pool.query('SELECT id FROM blockedList WHERE list = ? LIMIT 1', [domain]);
      if (verify.length > 0) {
        console.log(`✅ Verified domain in database: ${domain} (ID: ${verify[0].id})`);
      } else {
        console.error(`❌ Failed to verify domain addition: ${domain}`);
      }
      
      return true;
    } else {
      console.log(`ℹ️  Domain already in blocklist: ${domain} (ID: ${existing[0].id})`);
      return false; // Already exists, but that's okay
    }
  } catch (error) {
    console.error('❌ Error adding to blocklist:', error);
    console.error('URL:', url);
    console.error('Extracted domain:', extractDomain(url));
    return false;
  }
}

// Handle malicious URL detection
async function handleMaliciousUrl(message, url, threatData, serverConfig) {
  try {
    // Log the incident first
    await logSecurityIncident(message, url, threatData, serverConfig);
    
    // Log security event to database
    await logSecurityEvent(
      'MALICIOUS_URL_DETECTED',
      message.guild.id,
      message.author.id,
      message.channel.id,
      {
        url: url,
        threat_data: threatData,
        message_content: message.content,
        user_tag: message.author.tag
      },
      'HIGH'
    );
    
    // Delete the message
    if (!serverConfig || serverConfig.auto_delete_messages !== false) {
      await message.delete().catch(err => console.error('❌ Error deleting message:', err));
    }
    
    // Kick the user
    if (!serverConfig || serverConfig.auto_kick !== false) {
      await kickUser(message);
      await updateDailyStats('users_kicked', 1);
    }
    
    // Optionally delete user's recent messages
    if (!serverConfig || serverConfig.auto_delete_messages !== false) {
      await deleteUserMessages(message);
    }
    
    console.log(`✅ Security action completed for user: ${message.author.tag}`);
  } catch (error) {
    console.error('❌ Error handling malicious URL:', error);
  }
}

// Log security incident with enhanced details
async function logSecurityIncident(message, url, threatData, serverConfig) {
  try {
    // Use configured log channel or fallback to default
    const logChannelId = serverConfig?.log_channel_id || process.env.DEFAULT_LOG_CHANNEL;
    
    if (!logChannelId) {
      console.warn('⚠️ No log channel configured - security incident not logged to Discord');
      return;
    }
    
    const logChannel = await message.client.channels.fetch(logChannelId);
    if (!logChannel) {
      console.error('❌ Log channel not found!');
      return;
    }

    // Get AI analysis of the URL
    const aiAnalysis = await getAIAnalysis(url, message.content, threatData);

    const roles = message.member ? message.member.roles.cache.map(role => role.name).join(', ') : 'No roles';
    const channelName = message.channel ? message.channel.name : 'Unknown';

    // Create threat summary
    let threatSummary = '';
    if (threatData.details) {
      if (threatData.details.threat_categories && threatData.details.threat_categories.length > 0) {
        threatSummary += `**Categories:** ${threatData.details.threat_categories.join(', ')}\n`;
      }
      if (threatData.details.positives && threatData.details.total) {
        threatSummary += `**Detection Rate:** ${threatData.details.positives}/${threatData.details.total} engines\n`;
      }
      if (threatData.source) {
        threatSummary += `**Source:** ${threatData.source}\n`;
      }
    }

    // Top detections
    let detectionDetails = '';
    if (threatData.details && threatData.details.detection_engines) {
      detectionDetails = threatData.details.detection_engines
        .slice(0, 3)
        .map(d => `• ${d.engine}: ${d.result}`)
        .join('\n');
    }

    const embed = new EmbedBuilder()
      .setColor(0xFF0000) // Red for security alert
      .setTitle('🚨 Security Alert: Malicious URL Detected')
      .setDescription('A user attempted to post a malicious URL and has been automatically removed from the server.')
      .addFields(
        { name: '👤 User', value: `${message.author.tag}\n(ID: ${message.author.id})`, inline: true },
        { name: '🏷️ Roles', value: roles || 'None', inline: true },
        { name: '📍 Channel', value: `#${channelName}`, inline: true },
        { name: '🔗 Malicious URL', value: `\`${url.length > 100 ? url.substring(0, 100) + '...' : url}\``, inline: false }
      );

    if (threatSummary) {
      embed.addFields({ name: '⚠️ Threat Analysis', value: threatSummary, inline: false });
    }

    if (detectionDetails) {
      embed.addFields({ name: '🔍 Top Detections', value: detectionDetails, inline: false });
    }

    embed.addFields(
      { name: '💬 Message Content', value: message.content ? `\`\`\`${message.content.substring(0, 500)}${message.content.length > 500 ? '...' : ''}\`\`\`` : 'No content', inline: false },
      { name: '🤖 AI Analysis', value: aiAnalysis || 'Analysis not available', inline: false }
    );

    // Configure actions taken based on server config
    let actionsTaken = [];
    if (!serverConfig || serverConfig.auto_delete_messages !== false) {
      actionsTaken.push('• Message deleted');
    }
    if (!serverConfig || serverConfig.auto_kick !== false) {
      actionsTaken.push('• User kicked');
      actionsTaken.push('• Recent messages deleted');
    }
    actionsTaken.push('• Domain added to blocklist');

    embed.addFields(
      { name: '⚡ Actions Taken', value: actionsTaken.join('\n'), inline: false },
      { name: '🕐 Timestamp', value: `<t:${Math.floor(Date.now() / 1000)}:F>`, inline: true }
    );

    if (threatData.details && threatData.details.permalink) {
      embed.addFields({ name: '🔗 VirusTotal Report', value: `[View Full Report](${threatData.details.permalink})`, inline: true });
    }

    embed.setFooter({ text: 'Security Bot - Automated Protection', iconURL: message.client.user.displayAvatarURL() })
      .setTimestamp();

    await logChannel.send({ embeds: [embed] });
    
    // Log to database with enhanced details
    try {
      await pool.query(
        'INSERT INTO blockedMessages (userID, userName, content, orgChannelID, guildID, threat_data) VALUES (?, ?, ?, ?, ?, ?)',
        [message.author.id, message.author.tag, message.content, message.channel.id, message.guild.id, JSON.stringify(threatData)]
      );
    } catch (dbError) {
      console.error('❌ Error logging to database:', dbError);
    }
    
    console.log('✅ Security incident logged successfully');
  } catch (error) {
    console.error('❌ Error logging security incident:', error);
  }
}

// Get AI analysis with enhanced context
async function getAIAnalysis(url, messageContent, threatData) {
  try {
    let contextInfo = '';
    if (threatData.details) {
      if (threatData.details.threat_categories) {
        contextInfo += `Threat categories: ${threatData.details.threat_categories.join(', ')}. `;
      }
      if (threatData.details.positives && threatData.details.total) {
        contextInfo += `${threatData.details.positives} out of ${threatData.details.total} security engines flagged this as malicious. `;
      }
    }

    const prompt = `Security Analysis Request:
URL: ${url}
Message Context: ${messageContent}
Threat Intelligence: ${contextInfo}

Provide a concise security assessment (max 150 chars) explaining:
1. What type of threat this appears to be
2. Why it's dangerous to users
3. Brief risk assessment

Keep it professional and clear for security logs.`;

    const response = await getAIResponse(prompt);
    return response ? response.substring(0, 200) : 'AI analysis unavailable';
  } catch (error) {
    console.error('❌ Error getting AI analysis:', error);
    return 'AI analysis failed';
  }
}

// AI Response function (existing)
export async function getAIResponse(prompt) {
  try {
    const response = await axios({
      method: "post",
      url: `${OLLAMA_SERVER_URL}/generate`,
      data: {
        model: "deepseek-v2",
        prompt: prompt,
        stream: false // Disable streaming for simpler response handling
      },
      headers: {
        "Content-Type": "application/json",
      },
      timeout: 30000 // 30 second timeout
    });

    // Handle non-streaming response
    if (response.data && response.data.response) {
      return response.data.response.trim();
    }

    console.warn('⚠️ Unexpected Ollama response format:', response.data);
    return "AI analysis unavailable - unexpected response format.";

  } catch (error) {
    if (error.code === 'ECONNREFUSED') {
      console.error("❌ Cannot connect to Ollama server - is it running?");
      return "AI analysis unavailable - server offline.";
    } else if (error.response && error.response.status === 404) {
      console.error("❌ Ollama endpoint not found - check server URL and model availability");
      return "AI analysis unavailable - model not found.";
    } else {
      console.error("❌ Error communicating with Ollama server:", error.message);
      return "AI analysis unavailable due to server error.";
    }
  }
}

// Kick user function
async function kickUser(message) {
  try {
    const member = await message.guild.members.fetch(message.author.id);
    if (member && member.kickable) {
      await member.kick('Posted malicious URL - automated security action');
      console.log(`👢 User kicked: ${message.author.tag}`);
    } else {
      console.warn(`⚠️ Cannot kick user: ${message.author.tag} (insufficient permissions or user not found)`);
    }
  } catch (error) {
    console.error('❌ Error kicking user:', error);
  }
}

// Delete user's recent messages
async function deleteUserMessages(message) {
  try {
    const guild = message.guild;
    const channels = await guild.channels.fetch();
    const sevenDaysAgo = Date.now() - (7 * 24 * 60 * 60 * 1000);

    const deletePromises = channels
      .filter(channel => channel && channel.isTextBased())
      .map(async (channel) => {
        try {
          const messages = await channel.messages.fetch({ limit: 100 });
          const userMessages = messages.filter(msg => 
            msg.author.id === message.author.id && 
            msg.createdTimestamp > sevenDaysAgo
          );

          if (userMessages.size > 0) {
            await channel.bulkDelete(userMessages, true);
            console.log(`🗑️ Deleted ${userMessages.size} messages from #${channel.name}`);
          }
        } catch (error) {
          console.error(`❌ Error deleting messages in channel #${channel.name}:`, error);
        }
      });

    await Promise.all(deletePromises);
    console.log(`✅ Completed message cleanup for user: ${message.author.tag}`);
  } catch (error) {
    console.error('❌ Error in deleteUserMessages:', error);
  }
}

// Export rate limiter stats for monitoring
export function getRateLimiterStats() {
  return {
    requestsInWindow: rateLimiter.requests.length,
    maxRequests: rateLimiter.maxRequests,
    dailyRequests: rateLimiter.dailyRequests,
    maxDailyRequests: rateLimiter.maxDailyRequests,
    cacheSize: urlScanCache.size,
    scanQueueSize: scanQueue.size
  };
}

// Test function to manually add a domain to blocklist (for debugging)
export async function testAddToBlocklist(testUrl) {
  console.log(`🧪 Testing blocklist functionality with URL: ${testUrl}`);
  const result = await addToBlocklist(testUrl);
  console.log(`🧪 Test result: ${result ? 'SUCCESS' : 'FAILED'}`);
  
  // Also test extraction
  const domain = extractDomain(testUrl);
  console.log(`🧪 Domain extraction test: ${domain}`);
  
  // Verify in database
  try {
    const [rows] = await pool.query('SELECT * FROM blockedList WHERE list = ?', [domain]);
    console.log(`🧪 Database verification: ${rows.length > 0 ? 'FOUND' : 'NOT FOUND'}`);
    if (rows.length > 0) {
      console.log(`🧪 Database entry:`, rows[0]);
    }
  } catch (error) {
    console.error('🧪 Database verification failed:', error);
  }
  
  return result;
}

// Health check function for the security module
export function getSecurityHealth() {
  return {
    cacheSize: urlScanCache.size,
    scanQueueSize: scanQueue.size,
    dailyRequests: rateLimiter.dailyRequests,
    maxDailyRequests: rateLimiter.maxDailyRequests,
    requestsInWindow: rateLimiter.requests.length,
    maxRequests: rateLimiter.maxRequests,
    healthy: urlScanCache.size < MAX_CACHE_SIZE && scanQueue.size < 100
  };
}
