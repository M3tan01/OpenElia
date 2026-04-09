import { spawn, spawnSync } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import chalk from 'chalk';
import ora from 'ora';
import inquirer from 'inquirer';

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
  force?: boolean;
  args?: string;
  credAlias?: string;
}

export class OpenEliaCLI {
  private pythonPath: string;
  private projectRoot: string;
  private currentAgent: string = 'Pentester';

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
      console.error(chalk.red('Error:'), error.message);
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
      console.error(chalk.red('Error:'), error.message);
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
      console.error(chalk.red('Error:'), error.message);
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
      console.error(chalk.red('Error:'), error.message);
    }
  }

  async handleStatus(): Promise<void> {
    try {
      const result = await this.runPythonCommand(['status']);
      console.log(result.stdout);
    } catch (error) {
      console.error(chalk.red('Error:'), error.message);
    }
  }

  async handleDashboard(): Promise<void> {
    console.log(chalk.blue('🚀 Launching OpenElia War Room Dashboard...'));

    try {
      const result = await this.runPythonCommand(['dashboard']);
      console.log(result.stdout);
    } catch (error) {
      console.error(chalk.red('Error:'), error.message);
    }
  }

  async handleClear(options: CLIOptions): Promise<void> {
    try {
      const args = ['clear'];
      if (options.force) args.push('--force');

      const result = await this.runPythonCommand(args);
      console.log(result.stdout);
    } catch (error) {
      console.error(chalk.red('Error:'), error.message);
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
      console.error(chalk.red('Error:'), error.message);
    }
  }

  async handleMetasploit(options: CLIOptions): Promise<void> {
    const spinner = ora(`Running Metasploit against ${options.target}...`).start();

    try {
      const args = ['msf', '--target', options.target!];

      if (options.args) args.push('--args', options.args);
      if (options.credAlias) args.push('--cred-alias', options.credAlias);

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
      console.error(chalk.red('Error:'), error.message);
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

  async startInteractive(): Promise<void> {
    console.log(chalk.bold.blue('🛡️ Welcome to OpenElia CLI'));
    console.log(chalk.gray('Type "help" for commands or "exit" to quit\n'));

    while (true) {
      try {
        const { command } = await inquirer.prompt([
          {
            type: 'input',
            name: 'command',
            message: chalk.cyan(`${this.currentAgent}>`),
            validate: (input) => input.length > 0
          }
        ]);

        const trimmed = command.trim();

        if (trimmed === 'exit' || trimmed === 'quit') {
          console.log(chalk.yellow('Goodbye! 👋'));
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
        console.log(chalk.yellow('Unknown command. Type "help" for available commands.'));

      } catch (error) {
        console.error(chalk.red('Error:'), error.message);
        break;
      }
    }
  }

  private showHelp(): void {
    console.log(chalk.bold('\n📋 Available Commands:'));
    console.log(chalk.gray('  help                    Show this help'));
    console.log(chalk.gray('  status                  Show engagement status'));
    console.log(chalk.gray('  check                   Run readiness check'));
    console.log(chalk.gray('  agent <name>            Switch agent (Pentester/Defender/Reporter)'));
    console.log(chalk.gray('  exit/quit               Exit interactive mode'));
    console.log(chalk.gray('\n💡 Use command-line flags for full functionality:'));
    console.log(chalk.gray('  openelia-cli red --target 10.10.10.50'));
    console.log(chalk.gray('  openelia-cli blue --logs /path/to/logs.txt'));
    console.log('');
  }
}