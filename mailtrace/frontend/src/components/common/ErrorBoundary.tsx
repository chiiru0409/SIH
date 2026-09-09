import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle, RefreshCw, Home } from 'lucide-react';

interface Props {
  children: ReactNode;
  fallbackTitle?: string;
  onReset?: () => void;
}

interface State {
  hasError: boolean;
  error?: Error;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('MailTrace ErrorBoundary caught an error:', error, errorInfo);
  }

  private handleReload = () => {
    try {
      localStorage.removeItem('mailtrace_custom_cases');
      localStorage.removeItem('mailtrace_custom_emails');
      localStorage.removeItem('mailtrace_custom_evidence');
    } catch {
      // ignore
    }
    if (this.props.onReset) {
      this.props.onReset();
    }
    window.location.reload();
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div className="p-8 max-w-2xl mx-auto my-12 rounded-xl bg-cyber-panel border border-red-500/40 shadow-2xl text-center space-y-6 animate-fadeIn">
          <div className="w-16 h-16 mx-auto rounded-2xl bg-red-950/60 border border-red-500/50 flex items-center justify-center text-red-400">
            <AlertTriangle className="w-8 h-8 animate-pulse" />
          </div>

          <div className="space-y-2">
            <h2 className="text-xl font-mono font-bold text-slate-100 uppercase tracking-wider">
              {this.props.fallbackTitle || 'Forensic Workspace Recovered'}
            </h2>
            <p className="text-xs font-mono text-slate-400 max-w-md mx-auto">
              A temporary rendering anomaly occurred while rendering forensic indicators. The workspace has protected your session.
            </p>
            {this.state.error?.message && (
              <div className="p-3 rounded bg-slate-950/80 border border-slate-800 text-[11px] font-mono text-red-400/90 truncate max-w-lg mx-auto mt-2">
                {this.state.error.message}
              </div>
            )}
          </div>

          <div className="flex items-center justify-center gap-3 pt-2">
            <button
              onClick={() => this.setState({ hasError: false })}
              className="px-4 py-2 rounded-lg font-mono text-xs font-bold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 flex items-center gap-2 transition"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Retry Rendering</span>
            </button>
            <button
              onClick={this.handleReload}
              className="px-4 py-2 rounded-lg font-mono text-xs font-bold bg-cyan-500 hover:bg-cyan-400 text-slate-950 border border-cyan-400 flex items-center gap-2 transition shadow-glow-accent"
            >
              <Home className="w-3.5 h-3.5" />
              <span>Reset & Reload Baseline</span>
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
