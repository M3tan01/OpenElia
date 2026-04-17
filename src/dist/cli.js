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
const fs = __importStar(require("fs"));
const os = __importStar(require("os"));
const readline = __importStar(require("readline"));
const chalk_1 = __importDefault(require("chalk"));
const ora_1 = __importDefault(require("ora"));
function errMsg(e) {
    return e instanceof Error ? e.message : String(e);
}
class OpenEliaCLI {
    pythonPath;
    projectRoot;
    currentAgent = 'Pentester';
    program;
    constructor() {
        this.projectRoot = path.resolve(__dirname, '..', '..');
        this.pythonPath = this.findPythonExecutable();
    }
    findPythonExecutable() {
        // Try to find Python executable
        const candidates = ['python3', 'python', 'py'];
        for (const candidate of candidates) {
            try {
                const result = (0, child_process_1.spawnSync)(candidate, ['--version'], { stdio: 'pipe' });
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
            console.error(chalk_1.default.red('Error:'), errMsg(error));
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
            console.error(chalk_1.default.red('Error:'), errMsg(error));
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
            console.error(chalk_1.default.red('Error:'), errMsg(error));
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
            console.error(chalk_1.default.red('Error:'), errMsg(error));
        }
    }
    async handleStatus() {
        try {
            const result = await this.runPythonCommand(['status']);
            console.log(result.stdout);
        }
        catch (error) {
            console.error(chalk_1.default.red('Error:'), errMsg(error));
        }
    }
    async handleLock() {
        try {
            const result = await this.runPythonCommand(['lock']);
            console.log(result.stdout);
        }
        catch (error) {
            console.error(chalk_1.default.red('Error:'), errMsg(error));
        }
    }
    async handleUnlock() {
        try {
            const result = await this.runPythonCommand(['unlock']);
            console.log(result.stdout);
        }
        catch (error) {
            console.error(chalk_1.default.red('Error:'), errMsg(error));
        }
    }
    async handleDashboard() {
        console.log(chalk_1.default.blue('🚀 Launching OpenElia War Room Dashboard...'));
        try {
            const result = await this.runPythonCommand(['dashboard']);
            console.log(result.stdout);
        }
        catch (error) {
            console.error(chalk_1.default.red('Error:'), errMsg(error));
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
            console.error(chalk_1.default.red('Error:'), errMsg(error));
        }
    }
    async handleDoctor() {
        const spinner = (0, ora_1.default)('Running environment repair...').start();
        try {
            const result = await this.runPythonCommand(['doctor']);
            spinner.stop();
            if (result.code === 0) {
                console.log(chalk_1.default.green('✅ Environment repair completed'));
                console.log(result.stdout);
            }
            else {
                console.log(chalk_1.default.red('❌ Environment repair failed'));
                console.log(result.stderr);
            }
        }
        catch (error) {
            spinner.stop();
            console.error(chalk_1.default.red('Error:'), errMsg(error));
        }
    }
    async handleSbom() {
        const spinner = (0, ora_1.default)('Generating Software Bill of Materials...').start();
        try {
            const result = await this.runPythonCommand(['sbom']);
            spinner.stop();
            if (result.code === 0) {
                console.log(chalk_1.default.green('✅ SBOM generated successfully'));
                console.log(result.stdout);
            }
            else {
                console.log(chalk_1.default.red('❌ SBOM generation failed'));
                console.log(result.stderr);
            }
        }
        catch (error) {
            spinner.stop();
            console.error(chalk_1.default.red('Error:'), errMsg(error));
        }
    }
    async handleArchive() {
        const spinner = (0, ora_1.default)('Packaging engagement archive...').start();
        try {
            const result = await this.runPythonCommand(['archive']);
            spinner.stop();
            if (result.code === 0) {
                console.log(chalk_1.default.green('✅ Engagement archived successfully'));
                console.log(result.stdout);
            }
            else {
                console.log(chalk_1.default.red('❌ Archiving failed'));
                console.log(result.stderr);
            }
        }
        catch (error) {
            spinner.stop();
            console.error(chalk_1.default.red('Error:'), errMsg(error));
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
            console.error(chalk_1.default.red('Error:'), errMsg(error));
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
            if (options.stealth)
                args.push('--stealth');
            if (options.proxyPort)
                args.push('--proxy-port', options.proxyPort);
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
            console.error(chalk_1.default.red('Error:'), errMsg(error));
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
    getHistoryFile() {
        return path.join(os.homedir(), '.openelia_history');
    }
    async startInteractive(program) {
        this.program = program;
        const W = chalk_1.default.white.bold;
        const DG = chalk_1.default.gray;
        const G = chalk_1.default.green.bold;
        const banner = `
${W('   ____                   _______ __      ')}
${W('  / __ \\____  ___  ____  / ____/ (_)___ _ ')}
${W(' / / / / __ \\/ _ \\/ __ \\/ __/ / / / __ `/ ')}
${W('/ /_/ / /_/ /  __/ / / / /___/ / / /_/ /  ')}
${W('\\____/ .___/\\___/_/ /_/_____/_/_/\\__,_/   ')}
${W('    /_/                                   ')}
    
    ${DG('Operations Framework | Version 1.0')}
    
    ${DG('--------------------------------------------------')}
    [ ${G('Initialization')} ] Core Modules Loaded
    ${DG('--------------------------------------------------')}
    
    Goal:    Initialize defensive agents.
    Connect: Type 'help' to view available modules.
    `;
        console.log(banner);
        const historyFile = this.getHistoryFile();
        let history = [];
        if (fs.existsSync(historyFile)) {
            history = fs.readFileSync(historyFile, 'utf8').split('\n').filter(Boolean);
        }
        const commands = program ? program.commands.map((cmd) => cmd.name()) : [
            'red', 'blue', 'purple', 'check', 'doctor', 'status', 'dashboard', 'clear', 'sbom', 'archive', 'nmap', 'msf', 'agent', 'lock', 'unlock', 'help', 'exit', 'quit'
        ];
        // Add aliases if available
        if (program) {
            program.commands.forEach((cmd) => {
                if (cmd.alias())
                    commands.push(cmd.alias());
            });
        }
        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout,
            terminal: true,
            history: history,
            completer: (line) => {
                const hits = commands.filter((c) => c.startsWith(line));
                return [hits.length ? hits : commands, line];
            }
        });
        // Manually add history to the readline interface
        // Note: In Node.js < 15.8.0, history is not automatically loaded from the array
        // We can't easily access the private history property safely in all versions
        // But for most modern versions it's fine.
        const prompt = () => {
            rl.setPrompt(chalk_1.default.cyan(`${this.currentAgent}> `));
            rl.prompt();
        };
        prompt();
        return new Promise((resolve) => {
            rl.on('line', async (line) => {
                const trimmed = line.trim();
                if (!trimmed) {
                    prompt();
                    return;
                }
                // Save to history file
                if (trimmed !== 'exit' && trimmed !== 'quit') {
                    fs.appendFileSync(historyFile, trimmed + '\n');
                }
                if (trimmed === 'exit' || trimmed === 'quit') {
                    console.log(chalk_1.default.yellow('Goodbye! 👋'));
                    rl.close();
                    return;
                }
                if (trimmed === 'help') {
                    this.showHelp();
                    prompt();
                    return;
                }
                const args = trimmed.split(/\s+/);
                const cmd = args[0];
                try {
                    if (cmd === 'agent') {
                        if (args[1]) {
                            await this.switchAgent(args[1]);
                        }
                        else {
                            console.log(chalk_1.default.red('Usage: agent <name>'));
                        }
                    }
                    else if (program) {
                        // Try to use commander to parse and execute the command
                        // We need to temporarily disable process.exit for commander
                        const originalExit = process.exit;
                        // @ts-ignore
                        process.exit = () => { };
                        try {
                            // We use ['node', 'index.js', ...args] to simulate CLI call
                            await program.parseAsync(['node', 'index.js', ...args]);
                        }
                        catch (err) {
                            // Commander might throw if command is not found or help is shown
                            if (err instanceof Error && err.name !== 'CommanderError') {
                                console.error(chalk_1.default.red('Error:'), err.message);
                            }
                        }
                        finally {
                            process.exit = originalExit;
                        }
                    }
                    else {
                        // Fallback for simple commands if program is not available
                        if (trimmed === 'status')
                            await this.handleStatus();
                        else if (trimmed === 'check')
                            await this.handleCheck();
                        else if (trimmed === 'lock')
                            await this.handleLock();
                        else if (trimmed === 'unlock')
                            await this.handleUnlock();
                        else
                            console.log(chalk_1.default.yellow('Unknown command. Type "help" for available commands.'));
                    }
                }
                catch (error) {
                    console.error(chalk_1.default.red('Error:'), errMsg(error));
                }
                prompt();
            });
            rl.on('close', () => {
                resolve();
            });
        });
    }
    showHelp() {
        console.log(chalk_1.default.bold('\n📋 Available Commands:'));
        if (this.program) {
            this.program.commands.forEach((cmd) => {
                const name = cmd.name().padEnd(20);
                const desc = cmd.description();
                console.log(chalk_1.default.gray(`  ${name}    ${desc}`));
            });
        }
        else {
            console.log(chalk_1.default.gray('  help                    Show this help'));
            console.log(chalk_1.default.gray('  status                  Show engagement status'));
            console.log(chalk_1.default.gray('  check                   Run readiness check'));
            console.log(chalk_1.default.gray('  agent <name>            Switch agent (Pentester/Defender/Reporter)'));
            console.log(chalk_1.default.gray('  exit/quit               Exit interactive mode'));
        }
        console.log(chalk_1.default.gray('\n💡 Use command-line flags for full functionality:'));
        console.log(chalk_1.default.gray('  red --target 10.10.10.50'));
        console.log(chalk_1.default.gray('  blue --logs /path/to/logs.txt'));
        console.log('');
    }
}
exports.OpenEliaCLI = OpenEliaCLI;
//# sourceMappingURL=cli.js.map