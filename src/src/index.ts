#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import { OpenEliaCLI } from './cli';

const program = new Command();

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
  .action(async (options) => {
    await cli.handleMetasploit(options);
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
    await cli.startInteractive();
  });

// Default action - start interactive mode
program.action(async () => {
  await cli.startInteractive();
});

// Error handling
program.exitOverride();

try {
  program.parse();
} catch (error) {
  if (error instanceof Error && (error as NodeJS.ErrnoException).code === 'commander.help') {
    program.outputHelp();
  } else {
    console.error(chalk.red('Error:'), error instanceof Error ? error.message : String(error));
    process.exit(1);
  }
}