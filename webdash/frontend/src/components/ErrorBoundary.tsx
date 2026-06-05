import { Component, ReactNode } from "react";

interface ErrorBoundaryProps {
  children: ReactNode;
  resetKey?: string | number;
}

interface ErrorBoundaryState {
  error: Error | null;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error("Error caught by boundary:", error);
    console.error("Component stack:", errorInfo.componentStack);
  }

  componentDidUpdate(prevProps: ErrorBoundaryProps) {
    if (prevProps.resetKey !== this.props.resetKey && this.state.error !== null) {
      this.setState({ error: null });
    }
  }

  render() {
    if (this.state.error) {
      return (
        <main className="flex-1 min-h-0 overflow-hidden p-3 animate-boot flex items-center justify-center">
          <div className="hud bg-surface border border-redteam/50 max-w-md w-full p-4 flex flex-col gap-3">
            <div className="flex items-baseline gap-2">
              <span className="font-display text-redteam glow uppercase tracking-[0.2em] text-sm">
                ⚠ panel crashed
              </span>
            </div>
            <div className="font-mono text-xs text-dim leading-relaxed break-all">
              {this.state.error.message || "Unknown error"}
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => this.setState({ error: null })}
                className="font-mono text-[11px] uppercase tracking-widest px-3 py-2 border border-amber/50 text-amber hover:bg-amber/10 transition-colors"
              >
                Try again
              </button>
              <button
                onClick={() => window.location.reload()}
                className="font-mono text-[11px] uppercase tracking-widest px-3 py-2 border border-line text-dim hover:text-amber/80 transition-colors"
              >
                Reload
              </button>
            </div>
          </div>
        </main>
      );
    }

    return this.props.children;
  }
}
