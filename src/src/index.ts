#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import { OpenEliaCLI } from './cli';

export const program = new Command();

program
  .name('openelia-cli')
  .description('Claude Code-style CLI for OpenElia cybersecurity platform')
  .version('1.0.0');

// Initialize the CLI
const cli = new OpenEliaCLI();

// Red Team Commands
program
  .command('red')
  .description('Launch red team engagement')
  .option('-t, --target <target>', 'Target IP or CIDR range')
  .option('-s, --scope <scope>', 'Engagement scope')
  .option('--task <task>', 'Specific task description')
  .option('--passive', 'Passive reconnaissance only')
  .option('--stealth', 'Enable OPSEC stealth mode')
  .option('--brain-tier <tier>', 'Intelligence level (local/expensive)', 'local')
  .option('--apt <profile>', 'Adversary persona profile')
  .option('--proxy-port <port>', 'SOCKS5 proxy port for lateral movement')
  .option('--resume', 'Resume existing engagement')
  .action(async (options) => {
    await cli.handleRedTeam(options);
  });

// Blue Team Commands
program
  .command('blue')
  .description('Launch blue team analysis')
  .option('-l, --logs <path>', 'Path to log file')
  .option('--log-text <text>', 'Log text content')
  .option('--brain-tier <tier>', 'Intelligence level (local/expensive)', 'local')
  .action(async (options) => {
    await cli.handleBlueTeam(options);
  });

// Purple Team Commands
program
  .command('purple')
  .description('Launch purple team simulation')
  .option('-t, --target <target>', 'Target IP or CIDR range')
  .option('-s, --scope <scope>', 'Engagement scope')
  .option('--task <task>', 'Specific task description')
  .option('--iterations <num>', 'Number of simulation iterations', '2')
  .option('--stealth', 'Enable OPSEC stealth mode')
  .option('--brain-tier <tier>', 'Intelligence level (local/expensive)', 'local')
  .option('--apt <profile>', 'Adversary persona profile')
  .option('--proxy-port <port>', 'SOCKS5 proxy port for lateral movement')
  .option('--resume', 'Resume existing engagement')
  .action(async (options) => {
    await cli.handlePurpleTeam(options);
  });

// Utility Commands
program
  .command('check')
  .description('Run operational readiness check')
  .action(async () => {
    await cli.handleCheck();
  });

program
  .command('doctor')
  .description('Auto-repair environment issues')
  .action(async () => {
    await cli.handleDoctor();
  });

program
  .command('status')
  .description('Show current engagement status')
  .action(async () => {
    await cli.handleStatus();
  });

program
  .command('dashboard')
  .description('Launch interactive dashboard')
  .action(async () => {
    await cli.handleDashboard();
  });

program
  .command('clear')
  .description('Clear engagement state')
  .option('-f, --force', 'Force clear without confirmation')
  .action(async (options) => {
    await cli.handleClear(options);
  });

program
  .command('sbom')
  .description('Generate Software Bill of Materials')
  .action(async () => {
    await cli.handleSbom();
  });

program
  .command('archive')
  .description('Package engagement archive')
  .action(async () => {
    await cli.handleArchive();
  });

program
  .command('lock')
  .description('Engage Global Kill-Switch')
  .action(async () => {
    await cli.handleLock();
  });

program
  .command('unlock')
  .description('Disengage Global Kill-Switch')
  .action(async () => {
    await cli.handleUnlock();
  });

// Specialized Tools
program
  .command('nmap')
  .description('Run nmap scan')
  .requiredOption('-t, --target <target>', 'Target IP or CIDR range')
  .option('--args <args>', 'Additional nmap arguments')
  .option('--stealth', 'Enable stealth mode')
  .option('--brain-tier <tier>', 'Intelligence level (local/expensive)', 'local')
  .action(async (options) => {
    await cli.handleNmap(options);
  });

program
  .command('msf')
  .description('Run Metasploit console')
  .requiredOption('-t, --target <target>', 'Target IP')
  .option('--args <args>', 'Metasploit commands')
  .option('--cred-alias <alias>', 'Credential alias')
  .option('--stealth', 'Enable stealth mode')
  .option('--proxy-port <port>', 'Proxy port')
  .action(async (options) => {
    await cli.handleMetasploit(options);
  });

program
  .command('report')
  .description('Generate engagement report with MITRE heatmap and chain of custody')
  .option('--task <task>', 'Specific report task or focus area')
  .option('--brain-tier <tier>', 'Intelligence level (local/expensive)', 'local')
  .action(async (options) => {
    await cli.handleReport(options);
  });

program
  .command('execute-remediation')
  .description('Execute an approved response action by its logged ID')
  .requiredOption('--action-id <id>', 'Response action row ID from write_response_action')
  .action(async (options) => {
    await cli.handleExecuteRemediation({ actionId: options.actionId });
  });

// Model Configuration
const modelCmd = program
  .command('model')
  .description('Manage model configuration (local / cloud / hybrid)');

modelCmd
  .command('status')
  .description('Show current model configuration')
  .action(async () => {
    await cli.handleModel({ modelAction: 'status' });
  });

modelCmd
  .command('set <tier> [args...]')
  .description('Set active model  |  set local <model>  |  set cloud <provider> <model>')
  .action(async (tier: string, args: string[]) => {
    await cli.handleModel({ modelAction: 'set', tier, modelArgs: args });
  });

modelCmd
  .command('auth <provider> <apiKey>')
  .description('Store provider API key in OS keychain  (openai / anthropic / google)')
  .action(async (provider: string, apiKey: string) => {
    await cli.handleModel({ modelAction: 'auth', provider, apiKey });
  });

modelCmd
  .command('hybrid')
  .description('Pin an agent to a specific provider:model')
  .requiredOption('--agent <name>', 'Agent name (Pentester / Defender / Reporter)')
  .requiredOption('--provider <provider>', 'Provider (local / openai / anthropic / google)')
  .requiredOption('--model <model>', 'Model name (e.g. gpt-4o, llama3.1:8b)')
  .action(async (options) => {
    await cli.handleModel({ modelAction: 'hybrid', agent: options.agent, provider: options.provider, modelName: options.model });
  });

// Agent Commands
program
  .command('agent')
  .description('Switch active agent context')
  .argument('<agent>', 'Agent name (Pentester/Defender/Reporter)')
  .action(async (agent) => {
    await cli.switchAgent(agent);
  });

// Interactive Mode
program
  .command('interactive')
  .alias('i')
  .description('Start interactive Claude Code-style session')
  .action(async () => {
    await cli.startInteractive(program);
  });

// Default action - start interactive mode
program.action(async () => {
  await cli.startInteractive(program);
});

// Error handling
program.exitOverride();

// Main entry point
(async () => {
  try {
    await program.parseAsync();
  } catch (error) {
    if (error instanceof Error && (error as any).code === 'commander.helpDisplayed') {
      process.exit(0);
    } else {
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  }
})();