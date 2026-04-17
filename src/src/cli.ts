import { spawn, spawnSync } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import * as readline from 'readline';
import chalk from 'chalk';
import ora from 'ora';
import inquirer from 'inquirer';

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

export interface CLIOptions {
  target?: string;
  scope?: string;
  task?: string;
  passive?: boolean;
  stealth?: boolean;
  brainTier?: string;
  apt?: string;
  resume?: boolean;
  logs?: string;
  logText?: string;
  iterations?: string;
  args?: string;
  credAlias?: string;
  proxyPort?: string;
  force?: boolean;
}

export class OpenEliaCLI {
  private pythonPath: string;
  private projectRoot: string;
  private currentAgent: string = 'Pentester';
  private program: any;

  constructor() {
    this.projectRoot = path.resolve(__dirname, '..', '..');
    this.pythonPath = this.findPythonExecutable();
  }

  private findPythonExecutable(): string {
    // Try to find Python executable
    const candidates = ['python3', 'python', 'py'];

    for (const candidate of candidates) {
      try {
        const result = spawnSync(candidate, ['--version'], { stdio: 'pipe' });
        if (result.status === 0) {
          return candidate;
        }
      } catch {
        continue;
      }
    }

    // Fallback to python3
    return 'python3';
  }

  private async runPythonCommand(args: string[]): Promise<{ stdout: string; stderr: string; code: number }> {
    return new Promise((resolve, reject) => {
      const pythonProcess = spawn(this.pythonPath, ['main.py', ...args], {
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

  async handleRedTeam(options: CLIOptions): Promise<void> {
    const spinner = ora('Launching red team engagement...').start();

    try {
      const args = ['red'];

      if (options.target) args.push('--target', options.target);
      if (options.scope) args.push('--scope', options.scope);
      if (options.task) args.push('--task', options.task);
      if (options.passive) args.push('--passive');
      if (options.stealth) args.push('--stealth');
      if (options.brainTier) args.push('--brain-tier', options.brainTier);
      if (options.apt) args.push('--apt', options.apt);
      if (options.resume) args.push('--resume');

      const result = await this.runPythonCommand(args);

      spinner.stop();

      if (result.code === 0) {
        console.log(chalk.green('✅ Red team engagement completed successfully'));
        console.log(result.stdout);
      } else {
        console.log(chalk.red('❌ Red team engagement failed'));
        console.log(result.stderr);
      }
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), errMsg(error));
    }
  }

  async handleBlueTeam(options: CLIOptions): Promise<void> {
    const spinner = ora('Launching blue team analysis...').start();

    try {
      const args = ['blue'];

      if (options.logs) args.push('--logs', options.logs);
      if (options.logText) args.push('--log-text', options.logText);
      if (options.brainTier) args.push('--brain-tier', options.brainTier);

      const result = await this.runPythonCommand(args);

      spinner.stop();

      if (result.code === 0) {
        console.log(chalk.green('✅ Blue team analysis completed successfully'));
        console.log(result.stdout);
      } else {
        console.log(chalk.red('❌ Blue team analysis failed'));
        console.log(result.stderr);
      }
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), errMsg(error));
    }
  }

  async handlePurpleTeam(options: CLIOptions): Promise<void> {
    const spinner = ora('Launching purple team simulation...').start();

    try {
      const args = ['purple'];

      if (options.target) args.push('--target', options.target);
      if (options.scope) args.push('--scope', options.scope);
      if (options.task) args.push('--task', options.task);
      if (options.iterations) args.push('--iterations', options.iterations);
      if (options.stealth) args.push('--stealth');
      if (options.brainTier) args.push('--brain-tier', options.brainTier);
      if (options.apt) args.push('--apt', options.apt);
      if (options.resume) args.push('--resume');

      const result = await this.runPythonCommand(args);

      spinner.stop();

      if (result.code === 0) {
        console.log(chalk.green('✅ Purple team simulation completed successfully'));
        console.log(result.stdout);
      } else {
        console.log(chalk.red('❌ Purple team simulation failed'));
        console.log(result.stderr);
      }
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), errMsg(error));
    }
  }

  async handleCheck(): Promise<void> {
    const spinner = ora('Running operational readiness check...').start();

    try {
      const result = await this.runPythonCommand(['check']);

      spinner.stop();

      if (result.code === 0) {
        console.log(chalk.green('✅ System ready'));
        console.log(result.stdout);
      } else {
        console.log(chalk.red('❌ System not ready'));
        console.log(result.stderr);
      }
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), errMsg(error));
    }
  }

  async handleStatus(): Promise<void> {
    try {
      const result = await this.runPythonCommand(['status']);
      console.log(result.stdout);
    } catch (error) {
      console.error(chalk.red('Error:'), errMsg(error));
    }
  }

  async handleLock(): Promise<void> {
    try {
      const result = await this.runPythonCommand(['lock']);
      console.log(result.stdout);
    } catch (error) {
      console.error(chalk.red('Error:'), errMsg(error));
    }
  }

  async handleUnlock(): Promise<void> {
    try {
      const result = await this.runPythonCommand(['unlock']);
      console.log(result.stdout);
    } catch (error) {
      console.error(chalk.red('Error:'), errMsg(error));
    }
  }

  async handleDashboard(): Promise<void> {
    console.log(chalk.blue('🚀 Launching OpenElia War Room Dashboard...'));

    try {
      const result = await this.runPythonCommand(['dashboard']);
      console.log(result.stdout);
    } catch (error) {
      console.error(chalk.red('Error:'), errMsg(error));
    }
  }

  async handleClear(options: CLIOptions): Promise<void> {
    try {
      const args = ['clear'];
      if (options.force) args.push('--force');

      const result = await this.runPythonCommand(args);
      console.log(result.stdout);
    } catch (error) {
      console.error(chalk.red('Error:'), errMsg(error));
    }
  }

  async handleDoctor(): Promise<void> {
    const spinner = ora('Running environment repair...').start();

    try {
      const result = await this.runPythonCommand(['doctor']);

      spinner.stop();

      if (result.code === 0) {
        console.log(chalk.green('✅ Environment repair completed'));
        console.log(result.stdout);
      } else {
        console.log(chalk.red('❌ Environment repair failed'));
        console.log(result.stderr);
      }
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), errMsg(error));
    }
  }

  async handleSbom(): Promise<void> {
    const spinner = ora('Generating Software Bill of Materials...').start();

    try {
      const result = await this.runPythonCommand(['sbom']);

      spinner.stop();

      if (result.code === 0) {
        console.log(chalk.green('✅ SBOM generated successfully'));
        console.log(result.stdout);
      } else {
        console.log(chalk.red('❌ SBOM generation failed'));
        console.log(result.stderr);
      }
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), errMsg(error));
    }
  }

  async handleArchive(): Promise<void> {
    const spinner = ora('Packaging engagement archive...').start();

    try {
      const result = await this.runPythonCommand(['archive']);

      spinner.stop();

      if (result.code === 0) {
        console.log(chalk.green('✅ Engagement archived successfully'));
        console.log(result.stdout);
      } else {
        console.log(chalk.red('❌ Archiving failed'));
        console.log(result.stderr);
      }
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), errMsg(error));
    }
  }

  async handleNmap(options: CLIOptions): Promise<void> {
    const spinner = ora(`Running nmap scan on ${options.target}...`).start();

    try {
      const args = ['nmap', '--target', options.target!];

      if (options.args) args.push('--args', options.args);
      if (options.stealth) args.push('--stealth');
      if (options.brainTier) args.push('--brain-tier', options.brainTier);

      const result = await this.runPythonCommand(args);

      spinner.stop();

      if (result.code === 0) {
        console.log(chalk.green('✅ Nmap scan completed successfully'));
        console.log(result.stdout);
      } else {
        console.log(chalk.red('❌ Nmap scan failed'));
        console.log(result.stderr);
      }
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), errMsg(error));
    }
  }

  async handleMetasploit(options: CLIOptions): Promise<void> {
    const spinner = ora(`Running Metasploit against ${options.target}...`).start();

    try {
      const args = ['msf', '--target', options.target!];

      if (options.args) args.push('--args', options.args);
      if (options.credAlias) args.push('--cred-alias', options.credAlias);
      if (options.stealth) args.push('--stealth');
      if (options.proxyPort) args.push('--proxy-port', options.proxyPort);

      const result = await this.runPythonCommand(args);

      spinner.stop();

      if (result.code === 0) {
        console.log(chalk.green('✅ Metasploit session completed successfully'));
        console.log(result.stdout);
      } else {
        console.log(chalk.red('❌ Metasploit session failed'));
        console.log(result.stderr);
      }
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), errMsg(error));
    }
  }

  async switchAgent(agent: string): Promise<void> {
    const validAgents = ['Pentester', 'Defender', 'Reporter'];

    if (!validAgents.includes(agent)) {
      console.log(chalk.red(`Invalid agent: ${agent}. Valid agents: ${validAgents.join(', ')}`));
      return;
    }

    this.currentAgent = agent;
    console.log(chalk.green(`🔄 Switched to ${agent} agent context`));
  }

  private getHistoryFile(): string {
    return path.join(os.homedir(), '.openelia_history');
  }

  async startInteractive(program?: any): Promise<void> {
    this.program = program;
    const W = chalk.white.bold;
    const DG = chalk.gray;
    const G = chalk.green.bold;

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
    let history: string[] = [];
    if (fs.existsSync(historyFile)) {
      history = fs.readFileSync(historyFile, 'utf8').split('\n').filter(Boolean);
    }

    const commands = program ? program.commands.map((cmd: any) => cmd.name()) : [
      'red', 'blue', 'purple', 'check', 'doctor', 'status', 'dashboard', 'clear', 'sbom', 'archive', 'nmap', 'msf', 'agent', 'lock', 'unlock', 'help', 'exit', 'quit'
    ];
    
    // Add aliases if available
    if (program) {
      program.commands.forEach((cmd: any) => {
        if (cmd.alias()) commands.push(cmd.alias());
      });
    }

    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: true,
      history: history,
      completer: (line: string) => {
        const hits = commands.filter((c: string) => c.startsWith(line));
        return [hits.length ? hits : commands, line];
      }
    });

    // Manually add history to the readline interface
    // Note: In Node.js < 15.8.0, history is not automatically loaded from the array
    // We can't easily access the private history property safely in all versions
    // But for most modern versions it's fine.

    const prompt = () => {
      rl.setPrompt(chalk.cyan(`${this.currentAgent}> `));
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
          console.log(chalk.yellow('Goodbye! 👋'));
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
            } else {
              console.log(chalk.red('Usage: agent <name>'));
            }
          } else if (program) {
            // Try to use commander to parse and execute the command
            // We need to temporarily disable process.exit for commander
            const originalExit = process.exit;
            // @ts-ignore
            process.exit = () => {};
            
            try {
              // We use ['node', 'index.js', ...args] to simulate CLI call
              await program.parseAsync(['node', 'index.js', ...args]);
            } catch (err) {
              // Commander might throw if command is not found or help is shown
              if (err instanceof Error && err.name !== 'CommanderError') {
                console.error(chalk.red('Error:'), err.message);
              }
            } finally {
              process.exit = originalExit;
            }
          } else {
            // Fallback for simple commands if program is not available
            if (trimmed === 'status') await this.handleStatus();
            else if (trimmed === 'check') await this.handleCheck();
            else if (trimmed === 'lock') await this.handleLock();
            else if (trimmed === 'unlock') await this.handleUnlock();
            else console.log(chalk.yellow('Unknown command. Type "help" for available commands.'));
          }
        } catch (error) {
          console.error(chalk.red('Error:'), errMsg(error));
        }

        prompt();
      });

      rl.on('close', () => {
        resolve();
      });
    });
  }

  private showHelp(): void {
    console.log(chalk.bold('\n📋 Available Commands:'));
    
    if (this.program) {
      this.program.commands.forEach((cmd: any) => {
        const name = cmd.name().padEnd(20);
        const desc = cmd.description();
        console.log(chalk.gray(`  ${name}    ${desc}`));
      });
    } else {
      console.log(chalk.gray('  help                    Show this help'));
      console.log(chalk.gray('  status                  Show engagement status'));
      console.log(chalk.gray('  check                   Run readiness check'));
      console.log(chalk.gray('  agent <name>            Switch agent (Pentester/Defender/Reporter)'));
      console.log(chalk.gray('  exit/quit               Exit interactive mode'));
    }

    console.log(chalk.gray('\n💡 Use command-line flags for full functionality:'));
    console.log(chalk.gray('  red --target 10.10.10.50'));
    console.log(chalk.gray('  blue --logs /path/to/logs.txt'));
    console.log('');
  }
}