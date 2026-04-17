#!/usr/bin/env node
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.program = void 0;
const commander_1 = require("commander");
const chalk_1 = __importDefault(require("chalk"));
const cli_1 = require("./cli");
exports.program = new commander_1.Command();
exports.program
    .name('openelia-cli')
    .description('Claude Code-style CLI for OpenElia cybersecurity platform')
    .version('1.0.0');
// Initialize the CLI
const cli = new cli_1.OpenEliaCLI();
// Red Team Commands
exports.program
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
exports.program
    .command('blue')
    .description('Launch blue team analysis')
    .option('-l, --logs <path>', 'Path to log file')
    .option('--log-text <text>', 'Log text content')
    .option('--brain-tier <tier>', 'Intelligence level (local/expensive)', 'local')
    .action(async (options) => {
    await cli.handleBlueTeam(options);
});
// Purple Team Commands
exports.program
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
exports.program
    .command('check')
    .description('Run operational readiness check')
    .action(async () => {
    await cli.handleCheck();
});
exports.program
    .command('doctor')
    .description('Auto-repair environment issues')
    .action(async () => {
    await cli.handleDoctor();
});
exports.program
    .command('status')
    .description('Show current engagement status')
    .action(async () => {
    await cli.handleStatus();
});
exports.program
    .command('dashboard')
    .description('Launch interactive dashboard')
    .action(async () => {
    await cli.handleDashboard();
});
exports.program
    .command('clear')
    .description('Clear engagement state')
    .option('-f, --force', 'Force clear without confirmation')
    .action(async (options) => {
    await cli.handleClear(options);
});
exports.program
    .command('sbom')
    .description('Generate Software Bill of Materials')
    .action(async () => {
    await cli.handleSbom();
});
exports.program
    .command('archive')
    .description('Package engagement archive')
    .action(async () => {
    await cli.handleArchive();
});
exports.program
    .command('lock')
    .description('Engage Global Kill-Switch')
    .action(async () => {
    await cli.handleLock();
});
exports.program
    .command('unlock')
    .description('Disengage Global Kill-Switch')
    .action(async () => {
    await cli.handleUnlock();
});
// Specialized Tools
exports.program
    .command('nmap')
    .description('Run nmap scan')
    .requiredOption('-t, --target <target>', 'Target IP or CIDR range')
    .option('--args <args>', 'Additional nmap arguments')
    .option('--stealth', 'Enable stealth mode')
    .option('--brain-tier <tier>', 'Intelligence level (local/expensive)', 'local')
    .action(async (options) => {
    await cli.handleNmap(options);
});
exports.program
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
// Agent Commands
exports.program
    .command('agent')
    .description('Switch active agent context')
    .argument('<agent>', 'Agent name (Pentester/Defender/Reporter)')
    .action(async (agent) => {
    await cli.switchAgent(agent);
});
// Interactive Mode
exports.program
    .command('interactive')
    .alias('i')
    .description('Start interactive Claude Code-style session')
    .action(async () => {
    await cli.startInteractive(exports.program);
});
// Default action - start interactive mode
exports.program.action(async () => {
    await cli.startInteractive(exports.program);
});
// Error handling
exports.program.exitOverride();
try {
    exports.program.parse();
}
catch (error) {
    if (error instanceof Error && error.code === 'commander.help') {
        exports.program.outputHelp();
    }
    else {
        console.error(chalk_1.default.red('Error:'), error instanceof Error ? error.message : String(error));
        process.exit(1);
    }
}
//# sourceMappingURL=index.js.map