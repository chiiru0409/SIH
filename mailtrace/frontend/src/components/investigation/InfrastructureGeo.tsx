import React from 'react';
import { ThreatIoc } from '../../types/intelligence';
import { Globe, MapPin, Server, ShieldAlert, ShieldCheck, Radio } from 'lucide-react';
import { Badge } from '../common/Badge';

interface InfrastructureGeoProps {
  ip: string;
  country?: string;
  city?: string;
  asn?: string;
  org?: string;
  isProxyOrTor?: boolean;
  latitude?: number;
  longitude?: number;
}

export const InfrastructureGeo: React.FC<InfrastructureGeoProps> = ({
  ip,
  country = 'Netherlands',
  city = 'Amsterdam',
  asn = 'AS49505 (HostRoyale Ltd)',
  org = 'Bulletproof Hosting Provider',
  isProxyOrTor = true,
  latitude = 52.3702,
  longitude = 4.8952
}) => {
  // Convert latitude/longitude to approximate SVG coordinates on a 1000x500 world map
  // Longitude: -180 to 180 -> 0 to 1000
  // Latitude: 90 to -90 -> 0 to 500
  const mapX = ((longitude + 180) / 360) * 1000;
  const mapY = ((90 - latitude) / 180) * 500;

  return (
    <div className="p-5 rounded-lg bg-cyber-panel border border-slate-800 space-y-4">
      <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
        <div className="flex items-center gap-2">
          <Globe className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold font-mono text-slate-200">
            Infrastructure & Geolocation Intelligence
          </h3>
        </div>
        <div className="flex items-center gap-2">
          {isProxyOrTor && (
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/40 font-bold animate-pulse">
              ANONYMIZER / TOR EXIT DETECTED
            </span>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left: Infrastructure Metadata (4 cols) */}
        <div className="lg:col-span-5 space-y-3">
          <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 space-y-2.5 text-xs font-mono">
            <div className="flex justify-between items-center pb-2 border-b border-slate-800">
              <span className="text-slate-400">Sending Node IP:</span>
              <span className="font-bold text-cyan-400">{ip}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-slate-400">Physical Location:</span>
              <span className="text-slate-200 font-semibold">{city}, {country}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-slate-400">Autonomous System (ASN):</span>
              <span className="text-slate-300 truncate max-w-[170px]">{asn}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-slate-400">Hosting Organization:</span>
              <span className="text-slate-300 truncate max-w-[170px]">{org}</span>
            </div>
            <div className="flex justify-between items-center pt-2 border-t border-slate-800">
              <span className="text-slate-400">Geo Coordinates:</span>
              <span className="text-slate-400">{latitude.toFixed(4)}° N, {longitude.toFixed(4)}° E</span>
            </div>
          </div>

          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-400 space-y-1">
            <div className="text-cyan-400 font-bold uppercase">Threat Feeds Corroboration</div>
            <div>• Listed on AbuseIPDB with 94% confidence score</div>
            <div>• Historical malicious relay activity observed in 3 other campaigns</div>
          </div>
        </div>

        {/* Right: SVG World Map (7 cols) */}
        <div className="lg:col-span-7 p-3 rounded-lg bg-slate-950 border border-slate-800 flex flex-col justify-between relative overflow-hidden min-h-[220px]">
          <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 mb-2">
            <span className="flex items-center gap-1.5 text-cyan-400 font-bold">
              <MapPin className="w-3.5 h-3.5" />
              <span>Geo-Spatial Threat Vector</span>
            </span>
            <span className="text-[10px] text-slate-400">Grid: WGS-84</span>
          </div>

          {/* Stylized World Vector Map Background */}
          <div className="relative w-full h-44 bg-slate-900/60 rounded border border-slate-800/80 overflow-hidden flex items-center justify-center">
            <svg
              viewBox="0 0 1000 500"
              className="w-full h-full opacity-30 text-slate-600"
              fill="currentColor"
            >
              {/* Simplified world continent paths */}
              <path d="M150,120 Q200,100 280,110 Q320,150 300,200 Q240,240 180,220 Z" />
              <path d="M220,260 Q280,260 270,380 Q220,440 200,360 Z" />
              <path d="M460,100 Q540,80 580,140 Q520,220 460,180 Z" />
              <path d="M460,220 Q560,220 540,360 Q480,420 440,300 Z" />
              <path d="M580,100 Q800,80 850,200 Q760,280 620,200 Z" />
              <path d="M740,320 Q840,310 820,400 Q740,420 720,360 Z" />
            </svg>

            {/* Pulsing Target Origin Pin */}
            <div
              className="absolute z-10 -translate-x-1/2 -translate-y-1/2 group cursor-pointer"
              style={{ left: `${(mapX / 1000) * 100}%`, top: `${(mapY / 500) * 100}%` }}
            >
              <div className="relative flex items-center justify-center">
                <span className="absolute w-6 h-6 rounded-full bg-red-500/40 animate-ping" />
                <span className="relative w-3.5 h-3.5 rounded-full bg-red-500 border-2 border-white shadow-glow-critical flex items-center justify-center" />
              </div>

              {/* Hover Tooltip */}
              <div className="absolute left-1/2 -translate-x-1/2 bottom-full mb-1 opacity-100 bg-slate-900 border border-slate-700 px-2 py-1 rounded text-[10px] font-mono text-slate-200 shadow-2xl whitespace-nowrap pointer-events-none">
                <div className="font-bold text-red-400">{ip}</div>
                <div>{city}, {country}</div>
              </div>
            </div>
          </div>

          <div className="mt-2 flex items-center justify-between text-[10px] font-mono text-slate-400">
            <span>Target Node: Primary Perimeter Gateway</span>
            <span className="text-emerald-400">Trace Complete (Latency: 42ms)</span>
          </div>
        </div>
      </div>
    </div>
  );
};
