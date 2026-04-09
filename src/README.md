# OpenElia TypeScript CLI

Claude Code-style command-line interface for the OpenElia cybersecurity platform.

## Installation

```bash
cd src
npm install
npm run build
npm link  # Optional: make globally available
```

## Usage

### Command Line Mode

```bash
# Red team engagement
openelia-cli red --target 10.10.10.50 --stealth

# Blue team analysis
openelia-cli blue --logs /path/to/logs.txt

# Purple team simulation
openelia-cli purple --target 10.10.10.0/24 --iterations 3

# Nmap scan
openelia-cli nmap --target 10.10.10.50

# Metasploit console
openelia-cli msf --target 10.10.10.50 --args "use exploit/windows/smb/ms17_010_eternalblue"

# System check
openelia-cli check

# Show status
openelia-cli status

# Launch dashboard
openelia-cli dashboard
```

### Interactive Mode

```bash
openelia-cli interactive
# or just
openelia-cli
```

In interactive mode, you can:
- Type commands without the `openelia-cli` prefix
- Switch between agents: `agent Pentester`
- Get help: `help`
- Exit: `exit` or `quit`

## Development

```bash
# Development mode
npm run dev

# Build for production
npm run build

# Clean build artifacts
npm run clean
```

## Architecture

The TypeScript CLI serves as the user interface layer that communicates with the Python backend engine. It provides:

- **Command parsing and validation**
- **Progress indicators and colored output**
- **Interactive mode with agent switching**
- **Error handling and user feedback**
- **Seamless integration with Python components**

The CLI maintains the same command structure as the Python CLI but adds enhanced user experience features typical of modern terminal applications.