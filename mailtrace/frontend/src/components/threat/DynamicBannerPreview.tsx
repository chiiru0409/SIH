import React from 'react';
import { ShieldAlert, AlertTriangle, Info, AlertOctagon, Sparkles } from 'lucide-react';
import type { WarningBannerInfo } from '../../types/api';

export interface DynamicBannerPreviewProps {
  banner?: WarningBannerInfo | null;
  className?: string;
}

export const DynamicBannerPreview: React.FC<DynamicBannerPreviewProps> = ({
  banner,
  className = '',
}) => {
  if (!banner) return null;

  const getIcon = () => {
    switch (banner.severity) {
      case 'CRITICAL':
        return <AlertOctagon className="w-5 h-5 text-red-400 shrink-0" />;
      case 'WARNING':
        return <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0" />;
      default:
        return <Info className="w-5 h-5 text-cyber-cyan shrink-0" />;
    }
  };

  return (
    <div
      className={`rounded-lg p-4 border transition duration-200 ${className}`}
      style={{
        backgroundColor: banner.bg_color || 'rgba(15, 23, 42, 0.8)',
        borderColor: banner.border_color || '#334155',
      }}
    >
      <div className="flex items-start space-x-3">
        {getIcon()}
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between gap-2 flex-wrap mb-1">
            <div
              className="font-mono text-xs font-bold uppercase tracking-wide"
              style={{ color: banner.color || '#38bdf8' }}
            >
              {banner.title}
            </div>
            <div className="flex items-center space-x-1.5">
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900/80 text-slate-300 border border-slate-700">
                GREATHORN INLINE DEFENSE
              </span>
            </div>
          </div>
          <p className="text-xs text-slate-200 leading-relaxed font-sans">
            {banner.message}
          </p>
          {Array.isArray(banner.tags) && banner.tags.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-2.5">
              {banner.tags.map((tag, idx) => (
                <span
                  key={idx}
                  className="px-1.5 py-0.5 rounded bg-slate-900/90 text-slate-300 font-mono text-[10px] border border-slate-700/60"
                >
                  #{tag}
                </span>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
