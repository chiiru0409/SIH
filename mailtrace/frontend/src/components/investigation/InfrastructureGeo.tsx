import React from 'react';
import { ThreatIoc } from '../../types/intelligence';
import { Globe, MapPin, Server, ShieldAlert, ShieldCheck, Radio, Network, ArrowRight } from 'lucide-react';
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
  const mapX = ((longitude + 180) / 360) * 1000;
  const mapY = ((90 - latitude) / 180) * 500;

  return (
    <div className="p-5 rounded-lg bg-cyber-panel border border-slate-800 space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800/80">
        <div className="flex items-center gap-2">
          <Globe className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold font-mono text-slate-200">
            Observed Infrastructure & Geolocation Trace
          </h3>
        </div>
        <div className="flex items-center gap-2">
          {isProxyOrTor && (
            <span className="text-[10px] font-mono px-2.5 py-0.5 rounded-full bg-red-500/20 text-red-400 border border-red-500/40 font-bold animate-pulse">
              ANONYMIZER / TOR EXIT DETECTED
            </span>
          )}
        </div>
      </div>

      {/* STEP-BY-STEP VISUAL INFRASTRUCTURE PIPELINE */}
      <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800">
        <span className="text-[10px] font-mono text-slate-400 uppercase font-bold tracking-wider block mb-2">
          Observed Delivery Infrastructure Path
        </span>
        <div className="flex items-center gap-2 text-xs font-mono flex-wrap">
          <span className="px-2.5 py-1 rounded bg-slate-900 border border-slate-700 text-slate-200 font-bold">
            1. EMAIL (Sender)
          </span>
          <ArrowRight className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
          <span className="px-2.5 py-1 rounded bg-slate-900 border border-slate-700 text-slate-200 font-bold">
            2. MAIL RELAY (Origin Node)
          </span>
          <ArrowRight className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
          <span className="px-2.5 py-1 rounded bg-cyan-950/80 border border-cyan-500/40 text-cyan-300 font-bold">
            3. IP: {ip}
          </span>
          <ArrowRight className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
          <span className="px-2.5 py-1 rounded bg-slate-900 border border-slate-700 text-slate-200 font-bold">
            4. ASN: {asn.split(' ')[0]}
          </span>
          <ArrowRight className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
          <span className="px-2.5 py-1 rounded bg-slate-900 border border-slate-700 text-slate-200 font-bold">
            5. LOCATION: {city}, {country}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left: Infrastructure Metadata (5 cols) */}
        <div className="lg:col-span-5 space-y-3">
          <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 space-y-2.5 text-xs font-mono">
            <div className="flex justify-between items-center pb-2 border-b border-slate-800">
              <span className="text-slate-400">Sending Relay IP:</span>
              <span className="font-bold text-cyan-400">{ip}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-slate-400">Observed Server Location:</span>
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

          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-400 space-y-1.5">
            <div className="text-cyan-400 font-bold uppercase text-[10px]">Plain-English Terminology</div>
            <div>• <strong className="text-slate-300">ASN:</strong> Identifies the network organization / ISP operating the observed server.</div>
            <div>• <strong className="text-slate-300">Observed Location:</strong> Shows the physical datacenter hosting the intermediate mail server.</div>
          </div>
        </div>

        {/* Right: SVG World Map (7 cols) */}
        <div className="lg:col-span-7 p-3 rounded-lg bg-slate-950 border border-slate-800 flex flex-col justify-between relative overflow-hidden min-h-[220px]">
          <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 mb-2">
            <span className="flex items-center gap-1.5 text-cyan-400 font-bold">
              <MapPin className="w-3.5 h-3.5" />
              <span>Observed Infrastructure Coordinates (WGS-84)</span>
            </span>
            <span className="text-[10px] text-slate-400">{city}, {country}</span>
          </div>

          {/* Stylized World Vector Map Background */}
          <div className="relative w-full h-44 bg-slate-900/60 rounded border border-slate-800/80 overflow-hidden flex items-center justify-center">
            <svg
              viewBox="0 0 1000 500"
              className="w-full h-full opacity-30 text-slate-600"
              fill="currentColor"
            >
              {/* Simplified world map silhouettes */}
              <path d="M150,120 Q180,80 240,100 Q280,130 260,200 Q220,240 180,200 Z" />
              <path d="M220,260 Q260,280 250,380 Q200,420 180,340 Z" />
              <path d="M480,90 Q580,80 620,150 Q560,220 480,180 Z" />
              <path d="M480,220 Q560,220 540,360 Q480,380 460,280 Z" />
              <path d="M680,120 Q820,100 860,220 Q780,280 680,220 Z" />
              <path d="M780,320 Q860,320 840,400 Q780,420 760,360 Z" />
            </svg>

            {/* Target Coordinate Crosshair Marker */}
            <div
              className="absolute transform -translate-x-1/2 -translate-y-1/2 flex items-center justify-center pointer-events-none"
              style={{ left: `${Math.max(5, Math.min(95, mapX / 10))}%`, top: `${Math.max(10, Math.min(90, mapY / 5))}%` }}
            >
              <span className="w-6 h-6 rounded-full bg-red-500/30 border border-red-500/60 animate-ping absolute" />
              <span className="w-3.5 h-3.5 rounded-full bg-red-500 border-2 border-white shadow-glow-critical relative" />

              {/* Tooltip */}
              <div className="absolute left-1/2 -translate-x-1/2 bottom-full mb-1 bg-slate-900 border border-slate-700 px-2 py-0.5 rounded text-[10px] font-mono text-slate-200 shadow-2xl whitespace-nowrap">
                <span className="font-bold text-red-400">{ip}</span> ({city}, {country})
              </div>
            </div>
          </div>

          <div className="mt-2 flex items-center justify-between text-[10px] font-mono text-slate-400">
            <span>Target Node: Ingress Perimeter Gateway</span>
            <span className="text-emerald-400">Trace Complete (Latency: 42ms)</span>
          </div>
        </div>
      </div>

      <div className="p-3 rounded bg-slate-950/80 border border-slate-800 text-[11px] font-mono text-slate-400">
        <strong className="text-slate-300">Forensic Disclaimer:</strong> Observed sending infrastructure geolocates to approximate routing facilities (data centers, relays, ISPs). It indicates technical infrastructure ownership, not the verified physical location or legal identity of the human sender.
      </div>
    </div>
  );
};
