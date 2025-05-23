import { Client, GatewayIntentBits, ActivityType, EmbedBuilder } from 'discord.js';
import { config } from 'dotenv';
import { initializeDatabase } from './db.js';
import { initializeSecurity, setUpdateThreatCounter, getRateLimiterStats } from './security.js';
import { initializeSetup } from './setup.js';

config();

// Create Discord client with necessary intents
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
    GatewayIntentBits.GuildMembers, // This is crucial for fetching member data
    GatewayIntentBits.DirectMessages
  ]
});

// Bot status tracking
let botStatus = {
  startTime: Date.now(),
  messagesProcessed: 0,
  threatsBlocked: 0,
  serversProtected: 0,
  lastStatusUpdate: Date.now()
};

// Status update interval (every 5 minutes)
const STATUS_UPDATE_INTERVAL = 5 * 60 * 1000;

// Ready event
client.once('ready', async () => {
  console.log(`🤖 Bot logged in as ${client.user.tag}`);
  console.log(`📊 Protecting ${client.guilds.cache.size} servers`);
  
  try {
    // Initialize database
    console.log('🗄️ Initializing database...');
    await initializeDatabase();
    
    // Initialize security module
    console.log('🔒 Initializing security module...');
    setUpdateThreatCounter(updateThreatCounter); // Set up callback to avoid circular imports
    await initializeSecurity(client);
    
    // Initialize setup module
    console.log('⚙️ Initializing setup module...');
    await initializeSetup(client);
    
    // Set initial bot activity
    await updateBotActivity();
    
    // Start status monitoring
    setInterval(updateBotActivity, STATUS_UPDATE_INTERVAL);
    setInterval(logBotStatus, 30 * 60 * 1000); // Log every 30 minutes
    
    console.log('✅ Bot is fully operational!');
    
    // Send startup notification to log channel if configured
    await sendStartupNotification();
    
  } catch (error) {
    console.error('❌ Error during bot initialization:', error);
    process.exit(1);
  }
});

// Guild join event (for setup)
client.on('guildCreate', async (guild) => {
  console.log(`📈 Joined new server: ${guild.name} (${guild.id})`);
  botStatus.serversProtected = client.guilds.cache.size;
  
  try {
    // Send setup DM to guild owner
    const owner = await guild.fetchOwner();
    if (owner) {
      const setupEmbed = new EmbedBuilder()
        .setColor(0x00FF00)
        .setTitle('🎉 Thanks for adding Security Bot!')
        .setDescription(`Hello ${owner.user.username}!\n\nI've been added to **${guild.name}** and I'm ready to protect your server from malicious URLs and threats.\n\n**Quick Setup Required:**\nTo get started, please click the setup button below to configure your server settings.`)
        .addFields(
          { name: '🔒 What I Do', value: '• Scan all URLs for malicious content\n• Automatically remove threats\n• Kick users posting malicious links\n• Maintain blocklist database\n• Provide detailed security logs', inline: false },
          { name: '⚡ Features', value: '• Real-time VirusTotal scanning\n• AI-powered threat analysis\n• Automated threat response\n• Comprehensive logging\n• Rate limiting protection', inline: false },
          { name: '📋 Setup Steps', value: '1. Click "Setup Server" below\n2. Configure log channel\n3. Set admin roles\n4. Review settings\n5. You\'re protected!', inline: false }
        )
        .setFooter({ text: 'Security Bot - Automated Protection', iconURL: client.user.displayAvatarURL() })
        .setTimestamp();

      try {
        await owner.send({ 
          embeds: [setupEmbed],
          components: [{
            type: 1,
            components: [{
              type: 2,
              style: 1,
              label: '⚙️ Setup Server',
              custom_id: `setup_public`,
              emoji: { name: '⚙️' }
            }, {
              type: 2,
              style: 5,
              label: '📖 Documentation',
              url: 'https://github.com/yourusername/security-bot#readme'
            }]
          }]
        });
        console.log(`✅ Setup DM sent to ${owner.user.tag}`);
      } catch (dmError) {
        console.log(`❌ Could not send setup DM to ${owner.user.tag}:`, dmError.message);
        
        // Try to send setup message in a system channel instead
        const systemChannel = guild.systemChannel || 
                             guild.channels.cache.find(channel => 
                               channel.type === 0 && 
                               channel.permissionsFor(guild.members.me).has(['SendMessages', 'EmbedLinks'])
                             );
        
        if (systemChannel) {
          try {
            await systemChannel.send({
              content: `👋 Hello ${owner}! I couldn't send you a DM, so here's your setup information:`,
              embeds: [setupEmbed],
              components: [{
                type: 1,
                components: [{
                  type: 2,
                  style: 1,
                  label: '⚙️ Setup Server',
                  custom_id: `setup_public`,
                  emoji: { name: '⚙️' }
                }]
              }]
            });
            console.log(`✅ Setup message sent to #${systemChannel.name}`);
          } catch (channelError) {
            console.log(`❌ Could not send setup message to channel:`, channelError.message);
          }
        }
      }
    }
  } catch (error) {
    console.error('❌ Error handling guild join:', error);
  }
});

// Guild leave event
client.on('guildDelete', (guild) => {
  console.log(`📉 Left server: ${guild.name} (${guild.id})`);
  botStatus.serversProtected = client.guilds.cache.size;
});

// Message events for statistics
client.on('messageCreate', (message) => {
  if (!message.author.bot) {
    botStatus.messagesProcessed++;
  }
});

// Error handling
client.on('error', (error) => {
  console.error('❌ Discord client error:', error);
});

client.on('warn', (warning) => {
  console.warn('⚠️ Discord client warning:', warning);
});

// Process error handling
process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (error) => {
  console.error('❌ Uncaught Exception:', error);
  process.exit(1);
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('🔄 Received SIGINT, gracefully shutting down...');
  await sendShutdownNotification();
  client.destroy();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('🔄 Received SIGTERM, gracefully shutting down...');
  await sendShutdownNotification();
  client.destroy();
  process.exit(0);
});

// Update bot activity status
async function updateBotActivity() {
  try {
    const stats = getRateLimiterStats();
    const uptime = Math.floor((Date.now() - botStatus.startTime) / 1000);
    const hours = Math.floor(uptime / 3600);
    const minutes = Math.floor((uptime % 3600) / 60);
    
    const activities = [
      `🔒 Protecting ${client.guilds.cache.size} servers`,
      `🛡️ ${botStatus.threatsBlocked} threats blocked`,
      `📊 ${botStatus.messagesProcessed} messages scanned`,
      `⏱️ Uptime: ${hours}h ${minutes}m`,
      `🔍 Cache: ${stats.cacheSize} entries`
    ];
    
    const randomActivity = activities[Math.floor(Math.random() * activities.length)];
    
    await client.user.setActivity(randomActivity, { 
      type: ActivityType.Custom,
      state: randomActivity
    });
    
    // Update online status based on health
    const status = stats.requestsInWindow < stats.maxRequests ? 'online' : 'idle';
    await client.user.setStatus(status);
    
    botStatus.lastStatusUpdate = Date.now();
  } catch (error) {
    console.error('❌ Error updating bot activity:', error);
  }
}

// Log bot status periodically
function logBotStatus() {
  const stats = getRateLimiterStats();
  const uptime = Math.floor((Date.now() - botStatus.startTime) / 1000);
  
  console.log('📊 Bot Status Report:');
  console.log(`   🤖 Servers: ${client.guilds.cache.size}`);
  console.log(`   💬 Messages Processed: ${botStatus.messagesProcessed}`);
  console.log(`   🛡️ Threats Blocked: ${botStatus.threatsBlocked}`);
  console.log(`   ⏱️ Uptime: ${Math.floor(uptime / 3600)}h ${Math.floor((uptime % 3600) / 60)}m`);
  console.log(`   🔍 Cache Size: ${stats.cacheSize}`);
  console.log(`   📈 API Requests Today: ${stats.dailyRequests}/${stats.maxDailyRequests}`);
  console.log(`   🔄 Scan Queue: ${stats.scanQueueSize}`);
}

// Send startup notification
async function sendStartupNotification() {
  // Only send startup notification if we have servers and a configured channel
  if (client.guilds.cache.size === 0) {
    console.log('ℹ️ No servers joined yet - skipping startup notification');
    return;
  }

  const logChannelId = process.env.STARTUP_LOG_CHANNEL;
  if (!logChannelId) {
    console.log('ℹ️ No startup log channel configured - skipping startup notification');
    return;
  }
  
  try {
    const channel = await client.channels.fetch(logChannelId);
    if (!channel) {
      console.warn('⚠️ Startup log channel not found - check STARTUP_LOG_CHANNEL in .env');
      return;
    }
    
    const embed = new EmbedBuilder()
      .setColor(0x00FF00)
      .setTitle('🚀 Security Bot Started')
      .setDescription('Bot has successfully started and is now protecting servers.')
      .addFields(
        { name: '📊 Stats', value: `• Servers: ${client.guilds.cache.size}\n• Startup Time: <t:${Math.floor(botStatus.startTime / 1000)}:F>`, inline: true },
        { name: '🔧 Modules', value: '• Database ✅\n• Security ✅\n• Setup ✅', inline: true },
        { name: '⚙️ Configuration', value: `• VirusTotal: ${process.env.VIRUSTOTAL_API_KEY ? '✅' : '❌'}\n• AI Analysis: ✅\n• Auto-kick: ✅`, inline: true }
      )
      .setFooter({ text: 'Security Bot', iconURL: client.user.displayAvatarURL() })
      .setTimestamp();
    
    await channel.send({ embeds: [embed] });
    console.log('✅ Startup notification sent');
  } catch (error) {
    console.error('❌ Error sending startup notification:', error.message);
  }
}

// Send shutdown notification
async function sendShutdownNotification() {
  // Only send shutdown notification if we have servers and a configured channel
  if (client.guilds.cache.size === 0) {
    console.log('ℹ️ No servers joined - skipping shutdown notification');
    return;
  }

  const logChannelId = process.env.STARTUP_LOG_CHANNEL;
  if (!logChannelId) {
    console.log('ℹ️ No startup log channel configured - skipping shutdown notification');
    return;
  }
  
  try {
    const channel = await client.channels.fetch(logChannelId);
    if (!channel) {
      console.warn('⚠️ Startup log channel not found');
      return;
    }
    
    const uptime = Math.floor((Date.now() - botStatus.startTime) / 1000);
    const embed = new EmbedBuilder()
      .setColor(0xFF0000)
      .setTitle('🔄 Security Bot Shutting Down')
      .setDescription('Bot is gracefully shutting down.')
      .addFields(
        { name: '📊 Session Stats', value: `• Messages Processed: ${botStatus.messagesProcessed}\n• Threats Blocked: ${botStatus.threatsBlocked}\n• Uptime: ${Math.floor(uptime / 3600)}h ${Math.floor((uptime % 3600) / 60)}m`, inline: false }
      )
      .setFooter({ text: 'Security Bot', iconURL: client.user.displayAvatarURL() })
      .setTimestamp();
    
    await channel.send({ embeds: [embed] });
    console.log('✅ Shutdown notification sent');
  } catch (error) {
    console.error('❌ Error sending shutdown notification:', error.message);
  }
}

// Export bot status for other modules
export function updateThreatCounter() {
  botStatus.threatsBlocked++;
}

export function getBotStatus() {
  return { ...botStatus };
}

// Login to Discord
client.login(process.env.DISCORD_TOKEN).catch(error => {
  console.error('❌ Failed to login to Discord:', error);
  process.exit(1);
});