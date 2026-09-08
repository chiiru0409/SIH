import React from 'react';
import { ShieldCheck, Database, Terminal, FileCode } from 'lucide-react';

export const Footer: React.FC = () => {
  return (
    <footer className="border-t border-cyber-border/80 bg-cyber-bg/95 py-8 mt-16 text-xs text-slate-400">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 pb-6 border-b border-cyber-border/40">
          
          {/* Col 1: Platform identity */}
          <div>
            <div className="flex items-center space-x-2 mb-2">
              <ShieldCheck className="w-4 h-4 text-cyber-cyan" />
              <span className="font-mono font-bold text-slate-200 uppercase tracking-wider">
                MAILTRACE FORENSIC ENGINE
              </span>
            </div>
            <p className="text-[11px] leading-relaxed text-slate-400">
              Deterministic MIME disassembly, RFC 5322 header parsing, cryptographic SPF/DKIM/DMARC authentication, NLP threat signal analysis, and campaign infrastructure correlation graph.
            </p>
          </div>

          {/* Col 2: Evidence Integrity & Standards */}
          <div>
            <div className="flex items-center space-x-2 mb-2">
              <FileCode className="w-4 h-4 text-cyber-violet" />
              <span className="font-mono font-bold text-slate-200 uppercase tracking-wider">
                EVIDENCE STANDARDS
              </span>
            </div>
            <p className="text-[11px] leading-relaxed text-slate-400">
              SHA-256 evidence anchoring guarantees chain-of-custody. Forensic reports distinctly separate empirical 
              <span className="text-emerald-400 font-mono font-semibold mx-1">FACTS</span> from heuristic 
              <span className="text-purple-400 font-mono font-semibold mx-1">INFERENCES</span>.
            </p>
          </div>

          {/* Col 3: Attribution Safeguards */}
          <div>
            <div className="flex items-center space-x-2 mb-2">
              <Terminal className="w-4 h-4 text-cyber-amber" />
              <span className="font-mono font-bold text-slate-200 uppercase tracking-wider">
                ATTRIBUTION SAFEGUARD
              </span>
            </div>
            <p className="text-[11px] leading-relaxed text-slate-400">
              GeoIP metadata indicates observed relay and server infrastructure locations, never physical attacker premises. Campaign clusters identify correlated technical indicators.
            </p>
          </div>

        </div>

        <div className="flex flex-col sm:flex-row items-center justify-between pt-6 text-[11px] text-slate-500 font-mono">
          <div>
            © 2026 MAILTRACE PLATFORM — ALL EVIDENCE SECURELY ANCHORED
          </div>
          <div className="flex items-center space-x-4 mt-2 sm:mt-0">
            <span>API v1.0.0</span>
            <span>•</span>
            <span>SQLITE DATABASE</span>
            <span>•</span>
            <span>NETWORKX CORRELATION</span>
          </div>
        </div>
      </div>
    </footer>
  );
};
