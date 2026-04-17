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
export declare class OpenEliaCLI {
    private pythonPath;
    private projectRoot;
    private currentAgent;
    private program;
    constructor();
    private findPythonExecutable;
    private runPythonCommand;
    handleRedTeam(options: CLIOptions): Promise<void>;
    handleBlueTeam(options: CLIOptions): Promise<void>;
    handlePurpleTeam(options: CLIOptions): Promise<void>;
    handleCheck(): Promise<void>;
    handleStatus(): Promise<void>;
    handleLock(): Promise<void>;
    handleUnlock(): Promise<void>;
    handleDashboard(): Promise<void>;
    handleClear(options: CLIOptions): Promise<void>;
    handleDoctor(): Promise<void>;
    handleSbom(): Promise<void>;
    handleArchive(): Promise<void>;
    handleNmap(options: CLIOptions): Promise<void>;
    handleMetasploit(options: CLIOptions): Promise<void>;
    switchAgent(agent: string): Promise<void>;
    private getHistoryFile;
    startInteractive(program?: any): Promise<void>;
    private showHelp;
}
//# sourceMappingURL=cli.d.ts.map