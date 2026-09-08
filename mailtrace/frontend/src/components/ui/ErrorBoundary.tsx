import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle, RefreshCw, RotateCcw, ShieldAlert } from 'lucide-react';
import { Button } from './Button';

export interface ErrorBoundaryProps {
  children: ReactNode;
  fallbackTitle?: string;
  onReset?: () => void;
  className?: string;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  public state: ErrorBoundaryState = {
    hasError: false,
    error: null,
    errorInfo: null,
  };

  public static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    this.setState({ errorInfo });
    // Log full diagnostic context to console for troubleshooting
    console.error('[MAILTRACE FRONTEND ERROR CAUGHT BY ERROR BOUNDARY]', {
      error: error?.message || error,
      stack: error?.stack,
      componentStack: errorInfo?.componentStack,
    });
  }

  public handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
    if (this.props.onReset) {
      this.props.onReset();
    }
  };

  public render() {
    if (this.state.hasError) {
      const title = this.props.fallbackTitle || 'INVESTIGATION VIEW ERROR';
      const isDev = process.env.NODE_ENV !== 'production';

      return (
        <div className={`w-full p-6 sm:p-8 rounded-xl bg-cyber-surface/90 border border-red-500/50 shadow-2xl backdrop-blur-md text-slate-200 space-y-6 ${this.props.className || ''}`}>
          
          {/* Header */}
          <div className="flex items-start space-x-4">
            <div className="w-12 h-12 rounded-xl bg-red-950/60 border border-red-500/50 flex items-center justify-center text-red-400 shrink-0 shadow-[0_0_15px_rgba(239,68,68,0.3)]">
              <ShieldAlert className="w-6 h-6" />
            </div>

            <div className="space-y-1 flex-1">
              <div className="flex items-center space-x-2">
                <span className="font-mono text-base font-bold text-red-400 uppercase tracking-wide">
                  {title}
                </span>
                <span className="px-2 py-0.2 rounded bg-red-950/80 border border-red-500/40 text-red-300 font-mono text-[10px] font-bold">
                  RENDER RECOVERY
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono leading-relaxed">
                A frontend rendering error occurred in this investigation component. The error was caught safely by the MailTrace Error Boundary without crashing the application shell.
              </p>
            </div>
          </div>

          {/* Dev Diagnostic Info */}
          {isDev && this.state.error && (
            <div className="p-4 rounded-lg bg-slate-900/90 border border-cyber-border font-mono text-xs space-y-2 overflow-x-auto max-h-48 overflow-y-auto">
              <div className="text-red-400 font-bold">
                {this.state.error.name}: {this.state.error.message}
              </div>
              {this.state.error.stack && (
                <pre className="text-[10px] text-slate-500 whitespace-pre-wrap">
                  {this.state.error.stack}
                </pre>
              )}
            </div>
          )}

          {/* Action Recovery Buttons */}
          <div className="flex flex-wrap items-center gap-3 pt-2 border-t border-cyber-border/40">
            <Button
              variant="primary"
              size="sm"
              icon={<RotateCcw className="w-4 h-4" />}
              onClick={this.handleReset}
            >
              RETURN TO ANALYSIS
            </Button>
            <Button
              variant="outline"
              size="sm"
              icon={<RefreshCw className="w-4 h-4" />}
              onClick={() => window.location.reload()}
            >
              Reload Page
            </Button>
          </div>

        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
