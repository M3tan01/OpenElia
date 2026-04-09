"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.OpenEliaCLI = void 0;
const child_process_1 = require("child_process");
const path = __importStar(require("path"));
const chalk_1 = __importDefault(require("chalk"));
const ora_1 = __importDefault(require("ora"));
const inquirer_1 = __importDefault(require("inquirer"));
class OpenEliaCLI {
    pythonPath;
    projectRoot;
    currentAgent = 'Pentester';
    constructor() {
        this.projectRoot = path.resolve(__dirname, '..', '..');
        this.pythonPath = this.findPythonExecutable();
    }
    findPythonExecutable() {
        // Try to find Python executable
        const candidates = ['python3', 'python', 'py'];
        for (const candidate of candidates) {
            try {
                const result = child_process_1.spawn.sync(candidate, ['--version'], { stdio: 'pipe' });
                if (result.status === 0) {
                    return candidate;
                }
            }
            catch {
                continue;
            }
        }
        // Fallback to python3
        return 'python3';
    }
    async runPythonCommand(args) {
        return new Promise((resolve, reject) => {
            const pythonProcess = (0, child_process_1.spawn)(this.pythonPath, ['main.py', ...args], {
                cwd: this.projectRoot,
                stdio: ['pipe', 'pipe', 'pipe']
            });
            let stdout = '';
            let stderr = '';
            pythonProcess.stdout?.on('data', (data) => {
                stdout += data.toString();
            });
            pythonProcess.stderr?.on('data', (data) => {
                stderr += data.toString();
            });
            pythonProcess.on('close', (code) => {
                resolve({ stdout, stderr, code: code || 0 });
            });
            pythonProcess.on('error', (error) => {
                reject(error);
            });
        });
    }
    async handleRedTeam(options) {
        const spinner = (0, ora_1.default)('Launching red team engagement...').start();
        try {
            const args = ['red'];
            if (options.target)
                args.push('--target', options.target);
            if (options.scope)
                args.push('--scope', options.scope);
            if (options.task)
                args.push('--task', options.task);
            if (options.passive)
                args.push('--passive');
            if (options.stealth)
                args.push('--stealth');
            if (options.brainTier)
                args.push('--brain-tier', options.brainTier);
            if (options.apt)
                args.push('--apt', options.apt);
            if (options.resume)
                args.push('--resume');
            const result = await this.runPythonCommand(args);
            spinner.stop();
            if (result.code === 0) {
                console.log(chalk_1.default.green('✅ Red team engagement completed successfully'));
                console.log(result.stdout);
            }
            else {
                console.log(chalk_1.default.red('❌ Red team engagement failed'));
                console.log(result.stderr);
            }
        }
        catch (error) {
            spinner.stop();
            console.error(chalk_1.default.red('Error:'), error.message);
        }
    }
    async handleBlueTeam(options) {
        const spinner = (0, ora_1.default)('Launching blue team analysis...').start();
        try {
            const args = ['blue'];
            if (options.logs)
                args.push('--logs', options.logs);
            if (options.logText)
                args.push('--log-text', options.logText);
            if (options.brainTier)
                args.push('--brain-tier', options.brainTier);
            const result = await this.runPythonCommand(args);
            spinner.stop();
            if (result.code === 0) {
                console.log(chalk_1.default.green('✅ Blue team analysis completed successfully'));
                console.log(result.stdout);
            }
            else {
                console.log(chalk_1.default.red('❌ Blue team analysis failed'));
                console.log(result.stderr);
            }
        }
        catch (error) {
            spinner.stop();
            console.error(chalk_1.default.red('Error:'), error.message);
        }
    }
    async handlePurpleTeam(options) {
        const spinner = (0, ora_1.default)('Launching purple team simulation...').start();
        try {
            const args = ['purple'];
            if (options.target)
                args.push('--target', options.target);
            if (options.scope)
                args.push('--scope', options.scope);
            if (options.task)
                args.push('--task', options.task);
            if (options.iterations)
                args.push('--iterations', options.iterations);
            if (options.stealth)
                args.push('--stealth');
            if (options.brainTier)
                args.push('--brain-tier', options.brainTier);
            if (options.apt)
                args.push('--apt', options.apt);
            if (options.resume)
                args.push('--resume');
            const result = await this.runPythonCommand(args);
            spinner.stop();
            if (result.code === 0) {
                console.log(chalk_1.default.green('✅ Purple team simulation completed successfully'));
                console.log(result.stdout);
            }
            else {
                console.log(chalk_1.default.red('❌ Purple team simulation failed'));
                console.log(result.stderr);
            }
        }
        catch (error) {
            spinner.stop();
            console.error(chalk_1.default.red('Error:'), error.message);
        }
    }
    async handleCheck() {
        const spinner = (0, ora_1.default)('Running operational readiness check...').start();
        try {
            const result = await this.runPythonCommand(['check']);
            spinner.stop();
            if (result.code === 0) {
                console.log(chalk_1.default.green('✅ System ready'));
                console.log(result.stdout);
            }
            else {
                console.log(chalk_1.default.red('❌ System not ready'));
                console.log(result.stderr);
            }
        }
        catch (error) {
            spinner.stop();
            console.error(chalk_1.default.red('Error:'), error.message);
        }
    }
    async handleStatus() {
        try {
            const result = await this.runPythonCommand(['status']);
            console.log(result.stdout);
        }
        catch (error) {
            console.error(chalk_1.default.red('Error:'), error.message);
        }
    }
    async handleDashboard() {
        console.log(chalk_1.default.blue('🚀 Launching OpenElia War Room Dashboard...'));
        try {
            const result = await this.runPythonCommand(['dashboard']);
            console.log(result.stdout);
        }
        catch (error) {
            console.error(chalk_1.default.red('Error:'), error.message);
        }
    }
    async handleClear(options) {
        try {
            const args = ['clear'];
            if (options.force)
                args.push('--force');
            const result = await this.runPythonCommand(args);
            console.log(result.stdout);
        }
        catch (error) {
            console.error(chalk_1.default.red('Error:'), error.message);
        }
    }
    async handleNmap(options) {
        const spinner = (0, ora_1.default)(`Running nmap scan on ${options.target}...`).start();
        try {
            const args = ['nmap', '--target', options.target];
            if (options.args)
                args.push('--args', options.args);
            if (options.stealth)
                args.push('--stealth');
            if (options.brainTier)
                args.push('--brain-tier', options.brainTier);
            const result = await this.runPythonCommand(args);
            spinner.stop();
            if (result.code === 0) {
                console.log(chalk_1.default.green('✅ Nmap scan completed successfully'));
                console.log(result.stdout);
            }
            else {
                console.log(chalk_1.default.red('❌ Nmap scan failed'));
                console.log(result.stderr);
            }
        }
        catch (error) {
            spinner.stop();
            console.error(chalk_1.default.red('Error:'), error.message);
        }
    }
    async handleMetasploit(options) {
        const spinner = (0, ora_1.default)(`Running Metasploit against ${options.target}...`).start();
        try {
            const args = ['msf', '--target', options.target];
            if (options.args)
                args.push('--args', options.args);
            if (options.credAlias)
                args.push('--cred-alias', options.credAlias);
            const result = await this.runPythonCommand(args);
            spinner.stop();
            if (result.code === 0) {
                console.log(chalk_1.default.green('✅ Metasploit session completed successfully'));
                console.log(result.stdout);
            }
            else {
                console.log(chalk_1.default.red('❌ Metasploit session failed'));
                console.log(result.stderr);
            }
        }
        catch (error) {
            spinner.stop();
            console.error(chalk_1.default.red('Error:'), error.message);
        }
    }
    async switchAgent(agent) {
        const validAgents = ['Pentester', 'Defender', 'Reporter'];
        if (!validAgents.includes(agent)) {
            console.log(chalk_1.default.red(`Invalid agent: ${agent}. Valid agents: ${validAgents.join(', ')}`));
            return;
        }
        this.currentAgent = agent;
        console.log(chalk_1.default.green(`🔄 Switched to ${agent} agent context`));
    }
    async startInteractive() {
        console.log(chalk_1.default.bold.blue('🛡️ Welcome to OpenElia CLI'));
        console.log(chalk_1.default.gray('Type "help" for commands or "exit" to quit\n'));
        while (true) {
            try {
                const { command } = await inquirer_1.default.prompt([
                    {
                        type: 'input',
                        name: 'command',
                        message: chalk_1.default.cyan(`${this.currentAgent}>`),
                        validate: (input) => input.length > 0
                    }
                ]);
                const trimmed = command.trim();
                if (trimmed === 'exit' || trimmed === 'quit') {
                    console.log(chalk_1.default.yellow('Goodbye! 👋'));
                    break;
                }
                if (trimmed === 'help') {
                    this.showHelp();
                    continue;
                }
                if (trimmed === 'status') {
                    await this.handleStatus();
                    continue;
                }
                if (trimmed === 'check') {
                    await this.handleCheck();
                    continue;
                }
                if (trimmed.startsWith('agent ')) {
                    const agent = trimmed.split(' ')[1];
                    await this.switchAgent(agent);
                    continue;
                }
                // For other commands, show help
                console.log(chalk_1.default.yellow('Unknown command. Type "help" for available commands.'));
            }
            catch (error) {
                console.error(chalk_1.default.red('Error:'), error.message);
                break;
            }
        }
    }
    showHelp() {
        console.log(chalk_1.default.bold('\n📋 Available Commands:'));
        console.log(chalk_1.default.gray('  help                    Show this help'));
        console.log(chalk_1.default.gray('  status                  Show engagement status'));
        console.log(chalk_1.default.gray('  check                   Run readiness check'));
        console.log(chalk_1.default.gray('  agent <name>            Switch agent (Pentester/Defender/Reporter)'));
        console.log(chalk_1.default.gray('  exit/quit               Exit interactive mode'));
        console.log(chalk_1.default.gray('\n💡 Use command-line flags for full functionality:'));
        console.log(chalk_1.default.gray('  openelia-cli red --target 10.10.10.50'));
        console.log(chalk_1.default.gray('  openelia-cli blue --logs /path/to/logs.txt'));
        console.log('');
    }
}
exports.OpenEliaCLI = OpenEliaCLI;
//# sourceMappingURL=cli.js.map