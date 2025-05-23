import { 
    EmbedBuilder, 
    ActionRowBuilder, 
    StringSelectMenuBuilder, 
    ButtonBuilder, 
    ButtonStyle,
    ChannelType,
    PermissionFlagsBits 
  } from 'discord.js';
  import { getServerConfig, updateServerConfig, logSecurityEvent } from './db.js';
  
  // Setup states for tracking multi-step setup
  const setupStates = new Map();
  
  // Initialize setup states with timestamp
  function createSetupState(userId, guildId, existingConfig = null) {
    return {
      guildId,
      step: 'welcome',
      startTime: Date.now(),
      config: existingConfig || {
        log_channel_id: null,
        admin_role_ids: [],
        immune_role_ids: [],
        auto_kick: true,
        auto_delete_messages: true,
        scan_enabled: true
      }
    };
  }
  
  export async function initializeSetup(client) {
    console.log('⚙️ Initializing setup module...');
  
    // Handle button interactions
    client.on('interactionCreate', async (interaction) => {
      if (!interaction.isButton() && !interaction.isStringSelectMenu()) return;
  
      try {
        if (interaction.customId.startsWith('setup_')) {
          await handleSetupInteraction(interaction);
        } else if (interaction.customId.startsWith('config_')) {
          await handleConfigInteraction(interaction);
        } else if (interaction.customId === 'select_server_setup') {
          await handleServerSelectionChoice(interaction);
        } else if (interaction.customId === 'config_log_channel') {
          // Handle log channel selection
          const state = setupStates.get(interaction.user.id);
          if (state) {
            await handleLogChannelSelection(interaction, state);
          } else {
            await interaction.reply({
              content: '❌ Setup session expired. Please start the setup process again.',
              ephemeral: true
            });
          }
        } else if (interaction.customId === 'config_admin_roles') {
          // Handle admin roles selection
          const state = setupStates.get(interaction.user.id);
          if (state) {
            await handleAdminRolesSelection(interaction, state);
          } else {
            await interaction.reply({
              content: '❌ Setup session expired. Please start the setup process again.',
              ephemeral: true
            });
          }
        } else if (interaction.customId === 'config_immune_roles') {
          // Handle immune roles selection
          const state = setupStates.get(interaction.user.id);
          if (state) {
            await handleImmuneRolesSelection(interaction, state);
          } else {
            await interaction.reply({
              content: '❌ Setup session expired. Please start the setup process again.',
              ephemeral: true
            });
          }
        }
      } catch (error) {
        console.error('❌ Error handling setup interaction:', error);
        
        if (!interaction.replied && !interaction.deferred) {
          await interaction.reply({
            content: '❌ An error occurred during setup. Please try again.',
            ephemeral: true
          });
        }
      }
    });
  
    console.log('✅ Setup module initialized');
  }
  
  // Handle initial setup button click
  async function handleSetupInteraction(interaction) {
    // If clicked from DMs, show server selection
    if (!interaction.guild) {
      await handleServerSelection(interaction);
      return;
    }
  
    // If clicked from within a server, check permissions and start setup
    if (!interaction.member.permissions.has(PermissionFlagsBits.Administrator)) {
      await interaction.reply({
        content: '❌ You need Administrator permissions to set up the security bot in this server.',
        ephemeral: true
      });
      return;
    }
  
    // Start setup process for the current guild where the button was clicked
    console.log(`🔧 Setup initiated by ${interaction.user.tag} for server: ${interaction.guild.name} (${interaction.guild.id})`);
    await startSetupWizard(interaction);
  }
  
  // Handle server selection choice
  async function handleServerSelectionChoice(interaction) {
    const selectedGuildId = interaction.values[0];
    const guild = interaction.client.guilds.cache.get(selectedGuildId);
    
    if (!guild) {
      await interaction.reply({
        content: '❌ Selected server not found. Please try again.',
        ephemeral: true
      });
      return;
    }
  
    // Fetch member to ensure we have current permissions
    try {
      const member = await guild.members.fetch(interaction.user.id);
      if (!member || !member.permissions.has(PermissionFlagsBits.Administrator)) {
        await interaction.reply({
          content: '❌ You no longer have Administrator permissions in that server.',
          ephemeral: true
        });
        return;
      }
    } catch (error) {
      await interaction.reply({
        content: '❌ Could not verify your permissions in that server.',
        ephemeral: true
      });
      return;
    }
  
    await startSetupForGuild(interaction, guild);
  }
  
  // Start setup for a specific guild
  async function startSetupForGuild(interaction, guild) {
    const existingConfig = await getServerConfig(guild.id);
  
    // Initialize setup state for the selected guild
    setupStates.set(interaction.user.id, createSetupState(
      interaction.user.id, 
      guild.id, 
      existingConfig
    ));
  
    const embed = new EmbedBuilder()
      .setColor(0x0099FF)
      .setTitle('🛡️ Security Bot Setup Wizard')
      .setDescription(`Welcome to the setup wizard for **${guild.name}**!\n\nI'll help you configure the security settings to protect your server from malicious links and threats.`)
      .addFields(
        { name: '📋 Setup Steps', value: '1️⃣ Configure log channel\n2️⃣ Set admin roles\n3️⃣ Set immune roles\n4️⃣ Configure security actions\n5️⃣ Review & confirm', inline: false },
        { name: '⚡ Current Status', value: existingConfig?.setup_completed ? '✅ Previously configured' : '❌ Not configured', inline: true },
        { name: '🔧 Estimated Time', value: '2-3 minutes', inline: true }
      )
      .setFooter({ text: `Setting up: ${guild.name}`, iconURL: interaction.client.user.displayAvatarURL() })
      .setTimestamp();
  
    const row = new ActionRowBuilder()
      .addComponents(
        new ButtonBuilder()
          .setCustomId('config_start')
          .setLabel('🚀 Start Setup')
          .setStyle(ButtonStyle.Primary),
        new ButtonBuilder()
          .setCustomId('config_cancel')
          .setLabel('❌ Cancel')
          .setStyle(ButtonStyle.Secondary)
      );
  
    await interaction.update({
      embeds: [embed],
      components: [row]
    });
  }
  async function handleServerSelection(interaction) {
    // Get all mutual guilds where the user has admin permissions
    const mutualGuilds = interaction.client.guilds.cache.filter(guild => {
      const member = guild.members.cache.get(interaction.user.id);
      return member && member.permissions.has(PermissionFlagsBits.Administrator);
    });
  
    if (mutualGuilds.size === 0) {
      await interaction.reply({
        content: '❌ You don\'t have Administrator permissions in any servers where this bot is present.',
        ephemeral: true
      });
      return;
    }
  
    // If only one server, auto-select it
    if (mutualGuilds.size === 1) {
      const guild = mutualGuilds.first();
      await startSetupForGuild(interaction, guild);
      return;
    }
  
    // Show server selection dropdown
    const serverOptions = mutualGuilds.first(25).map(guild => ({
      label: guild.name,
      value: guild.id,
      description: `${guild.memberCount} members`,
      emoji: '🛡️'
    }));
  
    const embed = new EmbedBuilder()
      .setColor(0x0099FF)
      .setTitle('🛡️ Select Server to Setup')
      .setDescription('Choose which server you want to configure the security bot for:')
      .addFields({
        name: '📋 Available Servers',
        value: `You have Administrator permissions in ${mutualGuilds.size} server(s) where this bot is present.`,
        inline: false
      });
  
    const selectMenu = new StringSelectMenuBuilder()
      .setCustomId('select_server_setup')
      .setPlaceholder('Choose a server to configure...')
      .addOptions(serverOptions);
  
    const row = new ActionRowBuilder().addComponents(selectMenu);
  
    await interaction.reply({
      embeds: [embed],
      components: [row],
      ephemeral: true
    });
  }
  
  // Start the setup wizard
  async function startSetupWizard(interaction) {
    const guild = interaction.guild;
    const existingConfig = await getServerConfig(guild.id);
  
    // Initialize setup state for the current guild
    setupStates.set(interaction.user.id, createSetupState(
      interaction.user.id, 
      guild.id, 
      existingConfig
    ));
  
    const embed = new EmbedBuilder()
      .setColor(0x0099FF)
      .setTitle('🛡️ Security Bot Setup Wizard')
      .setDescription(`Welcome to the setup wizard for **${guild.name}**!\n\nI'll help you configure the security settings to protect your server from malicious links and threats.`)
      .addFields(
        { name: '📋 Setup Steps', value: '1️⃣ Configure log channel\n2️⃣ Set admin roles\n3️⃣ Set immune roles\n4️⃣ Configure security actions\n5️⃣ Review & confirm', inline: false },
        { name: '⚡ Current Status', value: existingConfig?.setup_completed ? '✅ Previously configured' : '❌ Not configured', inline: true },
        { name: '🔧 Estimated Time', value: '2-3 minutes', inline: true }
      )
      .setFooter({ text: 'Security Bot Setup', iconURL: interaction.client.user.displayAvatarURL() })
      .setTimestamp();
  
    const row = new ActionRowBuilder()
      .addComponents(
        new ButtonBuilder()
          .setCustomId('config_start')
          .setLabel('🚀 Start Setup')
          .setStyle(ButtonStyle.Primary),
        new ButtonBuilder()
          .setCustomId('config_cancel')
          .setLabel('❌ Cancel')
          .setStyle(ButtonStyle.Secondary)
      );
  
    await interaction.reply({
      embeds: [embed],
      components: [row],
      ephemeral: true
    });
  }
  
  // Handle configuration interactions
  async function handleConfigInteraction(interaction) {
    const state = setupStates.get(interaction.user.id);
    
    if (!state) {
      await interaction.reply({
        content: '❌ Setup session expired. Please start the setup process again.',
        ephemeral: true
      });
      return;
    }
  
    const fullId = interaction.customId;
    const parts = fullId.split('_');
    const action = fullId.replace('config_', '');
  
    console.log(`Handling config interaction: ${fullId}, action: ${action}`);
  
    switch (action) {
      case 'start':
        await handleLogChannelStep(interaction, state);
        break;
      case 'log_channel':
        await handleLogChannelSelection(interaction, state);
        break;
      case 'admin_roles':
        await handleAdminRolesSelection(interaction, state);
        break;
      case 'immune_roles':
        await handleImmuneRolesSelection(interaction, state);
        break;
      case 'toggle_kick':
        await handleToggleKick(interaction, state);
        break;
      case 'toggle_delete':
        await handleToggleDelete(interaction, state);
        break;
      case 'toggle_scan':
        await handleToggleScan(interaction, state);
        break;
      case 'security_settings':
        await handleSecuritySettingsStep(interaction, state);
        break;
      case 'review':
        await handleReviewStep(interaction, state);
        break;
      case 'confirm':
        await handleFinalConfirmation(interaction, state);
        break;
      case 'cancel':
        await handleCancel(interaction);
        break;
      case 'skip':
        await handleSkip(interaction, state);
        break;
      default:
        console.log(`Unknown config action: ${action} (full ID: ${fullId})`);
        await interaction.reply({
          content: `❌ Unknown setup action: ${action}`,
          ephemeral: true
        });
    }
  }
  
  // Step 1: Log Channel Configuration
  async function handleLogChannelStep(interaction, state) {
    const guild = interaction.client.guilds.cache.get(state.guildId);
    
    if (!guild) {
      await interaction.update({
        embeds: [new EmbedBuilder()
          .setColor(0xFF0000)
          .setTitle('❌ Server Not Found')
          .setDescription('The server you\'re trying to configure could not be found.')
        ],
        components: []
      });
      return;
    }
  
    const textChannels = guild.channels.cache
      .filter(channel => channel.type === ChannelType.GuildText)
      .filter(channel => channel.permissionsFor(guild.members.me).has([PermissionFlagsBits.SendMessages, PermissionFlagsBits.EmbedLinks]))
      .first(24); // Leave room for the "skip" option (24 + 1 = 25 max)
  
    if (textChannels.length === 0) {
      await interaction.update({
        embeds: [new EmbedBuilder()
          .setColor(0xFF0000)
          .setTitle('❌ No Suitable Channels Found')
          .setDescription('I need at least one text channel where I can send messages and embed links.')
          .addFields({ name: '🔧 Required Permissions', value: '• Send Messages\n• Embed Links\n• View Channel', inline: false })
        ],
        components: [new ActionRowBuilder().addComponents(
          new ButtonBuilder()
            .setCustomId('config_cancel')
            .setLabel('❌ Cancel Setup')
            .setStyle(ButtonStyle.Danger)
        )]
      });
      return;
    }
  
    const options = textChannels.map(channel => ({
      label: `#${channel.name}`,
      value: channel.id,
      description: `${channel.topic ? channel.topic.substring(0, 50) + '...' : 'No description'}`
    }));
  
    // Add option to skip
    options.push({
      label: '⏭️ Skip (no logging)',
      value: 'skip',
      description: 'Security events will not be logged to any channel'
    });
  
    // Double-check we don't exceed Discord's limit
    if (options.length > 25) {
      console.warn(`⚠️ Too many channel options (${options.length}), truncating to 25`);
      options.splice(24); // Keep first 24 + skip option
    }
  
    const embed = new EmbedBuilder()
      .setColor(0x0099FF)
      .setTitle('📝 Step 1: Security Log Channel')
      .setDescription('Choose a channel where **this server\'s** security alerts and logs will be sent.\n\n**Recommended:** Create a dedicated `#security-logs` channel for better organization.')
      .addFields(
        { name: '📋 What gets logged here:', value: '• Malicious URL detections on this server\n• User kicks and bans on this server\n• Security events on this server\n• Bot configuration changes', inline: false },
        { name: '🔒 Permissions needed:', value: '• Send Messages\n• Embed Links\n• View Channel', inline: false },
        { name: 'ℹ️ Important Note', value: 'This is separate from any global bot monitoring. Each server has its own security log channel.', inline: false }
      )
      .setFooter({ text: 'Step 1 of 4', iconURL: interaction.client.user.displayAvatarURL() });
  
    const selectMenu = new StringSelectMenuBuilder()
      .setCustomId('config_log_channel')
      .setPlaceholder('Select a log channel...')
      .addOptions(options);
  
    const row = new ActionRowBuilder().addComponents(selectMenu);
    const buttonRow = new ActionRowBuilder().addComponents(
      new ButtonBuilder()
        .setCustomId('config_cancel')
        .setLabel('❌ Cancel')
        .setStyle(ButtonStyle.Secondary)
    );
  
    await interaction.update({
      embeds: [embed],
      components: [row, buttonRow]
    });
  }
  
  // Handle log channel selection
  async function handleLogChannelSelection(interaction, state) {
    const channelId = interaction.values[0];
    
    if (channelId === 'skip') {
      state.config.log_channel_id = null;
    } else {
      const guild = interaction.client.guilds.cache.get(state.guildId);
      const channel = guild?.channels.cache.get(channelId);
      if (!channel) {
        await interaction.reply({
          content: '❌ Selected channel not found. Please try again.',
          ephemeral: true
        });
        return;
      }
      state.config.log_channel_id = channelId;
    }
  
    state.step = 'admin_roles';
    await handleAdminRolesStep(interaction, state);
  }
  
  // Step 2: Admin Roles Configuration
  async function handleAdminRolesStep(interaction, state) {
    const guild = interaction.client.guilds.cache.get(state.guildId);
    
    if (!guild) {
      await interaction.update({
        embeds: [new EmbedBuilder()
          .setColor(0xFF0000)
          .setTitle('❌ Server Not Found')
          .setDescription('The server you\'re trying to configure could not be found.')
        ],
        components: []
      });
      return;
    }
  
    const roles = guild.roles.cache
      .filter(role => !role.managed && role.id !== guild.id) // Exclude @everyone and bot roles
      .sort((a, b) => b.position - a.position)
      .first(19); // Leave room for the "skip" option (19 + 1 = 20, well under 25 limit)
  
    const options = roles.map(role => ({
      label: role.name,
      value: role.id,
      description: `${role.members.size} members • Position: ${role.position}`
    }));
  
    // Add skip option
    options.push({
      label: '⏭️ Skip (use Administrator permission)',
      value: 'skip',
      description: 'Users with Administrator permission can manage the bot'
    });
  
    // Ensure we don't exceed Discord's 25 option limit
    if (options.length > 25) {
      console.warn(`⚠️ Too many admin role options (${options.length}), truncating to 25`);
      options.splice(24); // Keep first 24 + skip option
    }
  
    const embed = new EmbedBuilder()
      .setColor(0x0099FF)
      .setTitle('👑 Step 2: Admin Roles')
      .setDescription('Select roles that can manage security bot settings and view logs.\n\n**Note:** Users with Administrator permission always have access.')
      .addFields(
        { name: '🔧 Admin Permissions', value: '• Configure bot settings\n• View security logs\n• Manage blocklist\n• Override security actions', inline: false },
        { name: '💡 Tip', value: 'Choose moderator or admin roles that should have bot management access.', inline: false }
      )
      .setFooter({ text: 'Step 2 of 4', iconURL: interaction.client.user.displayAvatarURL() });
  
    const selectMenu = new StringSelectMenuBuilder()
      .setCustomId('config_admin_roles')
      .setPlaceholder('Select admin roles...')
      .setMinValues(0)
      .setMaxValues(Math.min(options.length, 10))
      .addOptions(options);
  
    const row = new ActionRowBuilder().addComponents(selectMenu);
    const buttonRow = new ActionRowBuilder().addComponents(
      new ButtonBuilder()
        .setCustomId('config_cancel')
        .setLabel('❌ Cancel')
        .setStyle(ButtonStyle.Secondary)
    );
  
    await interaction.update({
      embeds: [embed],
      components: [row, buttonRow]
    });
  }
  
  // Handle admin roles selection
  async function handleAdminRolesSelection(interaction, state) {
    const selectedRoles = interaction.values.filter(value => value !== 'skip');
    state.config.admin_role_ids = selectedRoles;
    state.step = 'immune_roles';
    await handleImmuneRolesStep(interaction, state);
  }
  
  // Step 3: Immune Roles Configuration
  async function handleImmuneRolesStep(interaction, state) {
    const guild = interaction.client.guilds.cache.get(state.guildId);
    
    if (!guild) {
      await interaction.update({
        embeds: [new EmbedBuilder()
          .setColor(0xFF0000)
          .setTitle('❌ Server Not Found')
          .setDescription('The server you\'re trying to configure could not be found.')
        ],
        components: []
      });
      return;
    }
  
    const roles = guild.roles.cache
      .filter(role => !role.managed && role.id !== guild.id)
      .sort((a, b) => b.position - a.position)
      .first(19); // Leave room for the "skip" option
  
    const options = roles.map(role => ({
      label: role.name,
      value: role.id,
      description: `${role.members.size} members • Position: ${role.position}`
    }));
  
    // Add skip option
    options.push({
      label: '⏭️ Skip (no immune roles)',
      value: 'skip',
      description: 'All users will be scanned for malicious links'
    });
  
    // Ensure we don't exceed Discord's 25 option limit
    if (options.length > 25) {
      console.warn(`⚠️ Too many immune role options (${options.length}), truncating to 25`);
      options.splice(24); // Keep first 24 + skip option
    }
  
    const embed = new EmbedBuilder()
      .setColor(0x0099FF)
      .setTitle('🛡️ Step 3: Immune Roles')
      .setDescription('Select roles that should be immune to URL scanning and security actions.\n\n**Warning:** Immune users can post any links without restriction.')
      .addFields(
        { name: '⚠️ Immune Role Effects', value: '• No URL scanning\n• No automatic kicks\n• No message deletion\n• Bypass all security measures', inline: false },
        { name: '💡 Recommended', value: 'Only give immunity to highly trusted roles like administrators or senior moderators.', inline: false }
      )
      .setFooter({ text: 'Step 3 of 4', iconURL: interaction.client.user.displayAvatarURL() });
  
    const selectMenu = new StringSelectMenuBuilder()
      .setCustomId('config_immune_roles')
      .setPlaceholder('Select immune roles...')
      .setMinValues(0)
      .setMaxValues(Math.min(options.length, 10))
      .addOptions(options);
  
    const row = new ActionRowBuilder().addComponents(selectMenu);
    const buttonRow = new ActionRowBuilder().addComponents(
      new ButtonBuilder()
        .setCustomId('config_cancel')
        .setLabel('❌ Cancel')
        .setStyle(ButtonStyle.Secondary)
    );
  
    await interaction.update({
      embeds: [embed],
      components: [row, buttonRow]
    });
  }
  
  // Handle immune roles selection
  async function handleImmuneRolesSelection(interaction, state) {
    const selectedRoles = interaction.values.filter(value => value !== 'skip');
    state.config.immune_role_ids = selectedRoles;
    state.step = 'security_settings';
    await handleSecuritySettingsStep(interaction, state);
  }
  
  // Step 4: Security Settings Configuration
  async function handleSecuritySettingsStep(interaction, state) {
    const embed = new EmbedBuilder()
      .setColor(0x0099FF)
      .setTitle('⚙️ Step 4: Security Actions')
      .setDescription('Configure what actions the bot should take when malicious content is detected.')
      .addFields(
        { name: '🔄 Current Settings', value: getSecuritySettingsDisplay(state.config), inline: false },
        { name: '💡 Recommendations', value: '• **Auto-kick**: ✅ Recommended for maximum protection\n• **Delete messages**: ✅ Prevents spread of malicious links\n• **URL scanning**: ✅ Essential for threat detection', inline: false }
      )
      .setFooter({ text: 'Step 4 of 4', iconURL: interaction.client.user.displayAvatarURL() });
  
    const buttonRow1 = new ActionRowBuilder().addComponents(
      new ButtonBuilder()
        .setCustomId('config_toggle_kick')
        .setLabel(`Auto-kick: ${state.config.auto_kick ? 'ON' : 'OFF'}`)
        .setStyle(state.config.auto_kick ? ButtonStyle.Success : ButtonStyle.Danger)
        .setEmoji('👢'),
      new ButtonBuilder()
        .setCustomId('config_toggle_delete')
        .setLabel(`Delete messages: ${state.config.auto_delete_messages ? 'ON' : 'OFF'}`)
        .setStyle(state.config.auto_delete_messages ? ButtonStyle.Success : ButtonStyle.Danger)
        .setEmoji('🗑️'),
      new ButtonBuilder()
        .setCustomId('config_toggle_scan')
        .setLabel(`URL scanning: ${state.config.scan_enabled ? 'ON' : 'OFF'}`)
        .setStyle(state.config.scan_enabled ? ButtonStyle.Success : ButtonStyle.Danger)
        .setEmoji('🔍')
    );
  
    const buttonRow2 = new ActionRowBuilder().addComponents(
      new ButtonBuilder()
        .setCustomId('config_review')
        .setLabel('📋 Review & Finish')
        .setStyle(ButtonStyle.Primary),
      new ButtonBuilder()
        .setCustomId('config_cancel')
        .setLabel('❌ Cancel')
        .setStyle(ButtonStyle.Secondary)
    );
  
    await interaction.update({
      embeds: [embed],
      components: [buttonRow1, buttonRow2]
    });
  }
  
  // Security settings display helper
  function getSecuritySettingsDisplay(config) {
    return [
      `👢 **Auto-kick malicious users:** ${config.auto_kick ? '✅ Enabled' : '❌ Disabled'}`,
      `🗑️ **Delete malicious messages:** ${config.auto_delete_messages ? '✅ Enabled' : '❌ Disabled'}`,
      `🔍 **URL scanning:** ${config.scan_enabled ? '✅ Enabled' : '❌ Disabled'}`
    ].join('\n');
  }
  
  // Toggle handlers
  async function handleToggleKick(interaction, state) {
    state.config.auto_kick = !state.config.auto_kick;
    await handleSecuritySettingsStep(interaction, state);
  }
  
  async function handleToggleDelete(interaction, state) {
    state.config.auto_delete_messages = !state.config.auto_delete_messages;
    await handleSecuritySettingsStep(interaction, state);
  }
  
  async function handleToggleScan(interaction, state) {
    state.config.scan_enabled = !state.config.scan_enabled;
    await handleSecuritySettingsStep(interaction, state);
  }
  
  // Review step
  async function handleReviewStep(interaction, state) {
    const guild = interaction.client.guilds.cache.get(state.guildId);
    
    if (!guild) {
      await interaction.update({
        embeds: [new EmbedBuilder()
          .setColor(0xFF0000)
          .setTitle('❌ Server Not Found')
          .setDescription('The server you\'re trying to configure could not be found.')
        ],
        components: []
      });
      return;
    }
  
    const logChannel = state.config.log_channel_id ? guild.channels.cache.get(state.config.log_channel_id) : null;
    const adminRoles = state.config.admin_role_ids.map(id => guild.roles.cache.get(id)?.name || 'Unknown').join(', ') || 'None';
    const immuneRoles = state.config.immune_role_ids.map(id => guild.roles.cache.get(id)?.name || 'Unknown').join(', ') || 'None';
  
    const embed = new EmbedBuilder()
      .setColor(0x00FF00)
      .setTitle('📋 Configuration Review')
      .setDescription('Please review your security configuration before finalizing.')
      .addFields(
        { name: '📝 Log Channel', value: logChannel ? `#${logChannel.name}` : 'None (logging disabled)', inline: true },
        { name: '👑 Admin Roles', value: adminRoles.length > 50 ? adminRoles.substring(0, 50) + '...' : adminRoles, inline: true },
        { name: '🛡️ Immune Roles', value: immuneRoles.length > 50 ? immuneRoles.substring(0, 50) + '...' : immuneRoles, inline: true },
        { name: '⚙️ Security Actions', value: getSecuritySettingsDisplay(state.config), inline: false },
        { name: '⚠️ Important', value: 'After confirming, the bot will immediately start protecting your server according to these settings.', inline: false }
      )
      .setFooter({ text: 'Final Step - Review', iconURL: interaction.client.user.displayAvatarURL() });
  
    const buttonRow = new ActionRowBuilder().addComponents(
      new ButtonBuilder()
        .setCustomId('config_confirm')
        .setLabel('✅ Confirm & Activate')
        .setStyle(ButtonStyle.Success),
      new ButtonBuilder()
        .setCustomId('config_security_settings')
        .setLabel('🔙 Back to Settings')
        .setStyle(ButtonStyle.Secondary),
      new ButtonBuilder()
        .setCustomId('config_cancel')
        .setLabel('❌ Cancel')
        .setStyle(ButtonStyle.Danger)
    );
  
    await interaction.update({
      embeds: [embed],
      components: [buttonRow]
    });
  }
  
  // Final confirmation and save
  async function handleFinalConfirmation(interaction, state) {
    const guild = interaction.client.guilds.cache.get(state.guildId);
    
    if (!guild) {
      await interaction.update({
        embeds: [new EmbedBuilder()
          .setColor(0xFF0000)
          .setTitle('❌ Server Not Found')
          .setDescription('The server you\'re trying to configure could not be found.')
        ],
        components: []
      });
      return;
    }
    
    // Save configuration to database
    const success = await updateServerConfig(state.guildId, {
      ...state.config,
      setup_completed: true,
      setup_by: interaction.user.id
    });
  
    if (!success) {
      await interaction.update({
        embeds: [new EmbedBuilder()
          .setColor(0xFF0000)
          .setTitle('❌ Setup Failed')
          .setDescription('Failed to save configuration to database. Please try again.')
        ],
        components: []
      });
      return;
    }
  
    // Log security event
    await logSecurityEvent('SETUP_COMPLETED', guild.id, interaction.user.id, null, {
      config: state.config,
      setup_user: interaction.user.tag
    }, 'LOW');
  
    // Send success message
    const embed = new EmbedBuilder()
      .setColor(0x00FF00)
      .setTitle('✅ Setup Complete!')
      .setDescription(`Security Bot has been successfully configured for **${guild.name}**!`)
      .addFields(
        { name: '🛡️ Protection Status', value: '**ACTIVE** - Your server is now protected', inline: true },
        { name: '📊 Next Steps', value: '• Monitor security logs\n• Test with safe URLs\n• Adjust settings if needed', inline: true },
        { name: '🔗 Quick Test', value: 'Try posting a safe URL to see the bot in action (URLs are scanned in real-time)', inline: false }
      )
      .setFooter({ text: 'Security Bot - Active Protection', iconURL: interaction.client.user.displayAvatarURL() })
      .setTimestamp();
  
    await interaction.update({
      embeds: [embed],
      components: []
    });
  
    // Send confirmation to log channel if configured
    if (state.config.log_channel_id) {
      try {
        const logChannel = guild.channels.cache.get(state.config.log_channel_id);
        if (logChannel) {
          const logEmbed = new EmbedBuilder()
            .setColor(0x00FF00)
            .setTitle('🛡️ Security Bot Activated')
            .setDescription('Security monitoring has been activated for this server.')
            .addFields(
              { name: '👤 Configured by', value: `${interaction.user.tag}`, inline: true },
              { name: '⚙️ Auto-kick', value: state.config.auto_kick ? 'Enabled' : 'Disabled', inline: true },
              { name: '🗑️ Auto-delete', value: state.config.auto_delete_messages ? 'Enabled' : 'Disabled', inline: true }
            )
            .setTimestamp();
  
          await logChannel.send({ embeds: [logEmbed] });
        }
      } catch (error) {
        console.error('❌ Error sending setup confirmation to log channel:', error);
      }
    }
  
    // Clean up setup state
    setupStates.delete(interaction.user.id);
  }
  
  // Cancel setup
  async function handleCancel(interaction) {
    setupStates.delete(interaction.user.id);
    
    const embed = new EmbedBuilder()
      .setColor(0xFF0000)
      .setTitle('❌ Setup Cancelled')
      .setDescription('Security bot setup has been cancelled. No changes were made to your server configuration.')
      .addFields({ name: '🔄 Want to try again?', value: 'You can restart the setup process anytime by running the setup command or clicking the setup button.', inline: false });
  
    await interaction.update({
      embeds: [embed],
      components: []
    });
  }
  
  // Skip step handler
  async function handleSkip(interaction, state) {
    // Handle skip logic based on current step
    switch (state.step) {
      case 'log_channel':
        state.config.log_channel_id = null;
        state.step = 'admin_roles';
        await handleAdminRolesStep(interaction, state);
        break;
      case 'admin_roles':
        state.config.admin_role_ids = [];
        state.step = 'immune_roles';
        await handleImmuneRolesStep(interaction, state);
        break;
      case 'immune_roles':
        state.config.immune_role_ids = [];
        state.step = 'security_settings';
        await handleSecuritySettingsStep(interaction, state);
        break;
      default:
        await interaction.reply({
          content: '❌ Cannot skip this step.',
          ephemeral: true
        });
    }
  }
  
  // Cleanup expired setup states
  setInterval(() => {
    const now = Date.now();
    for (const [userId, state] of setupStates.entries()) {
      if (now - state.startTime > 30 * 60 * 1000) { // 30 minutes
        setupStates.delete(userId);
      }
    }
  }, 5 * 60 * 1000); // Check every 5 minutes