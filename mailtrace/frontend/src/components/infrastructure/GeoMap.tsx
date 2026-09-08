import React, { useState } from 'react';
import { Globe, MapPin, Compass, Navigation, Info } from 'lucide-react';
import { Card } from '../ui/Card';
import type { IPRecord } from '../../types/api';

export interface GeoMapProps {
  ips?: IPRecord[] | null;
  className?: string;
}

export const GeoMap: React.FC<GeoMapProps> = ({ ips, className }) => {
  const [hoveredIp, setHoveredIp] = useState<IPRecord | null>(null);

  const ipList = Array.isArray(ips) ? ips : [];

  // Filter IPs with valid, finite, numeric latitude & longitude
  const geoIps = ipList.filter(
    (item) => 
      item?.geo &&
      typeof item.geo.latitude === 'number' &&
      !isNaN(item.geo.latitude) &&
      isFinite(item.geo.latitude) &&
      typeof item.geo.longitude === 'number' &&
      !isNaN(item.geo.longitude) &&
      isFinite(item.geo.longitude)
  );

  // Convert lat/long to SVG Equirectangular coordinates (width 800, height 400)
  const mapWidth = 800;
  const mapHeight = 400;

  const projectCoord = (lat: number, lon: number) => {
    // x ranges from -180 to 180 -> 0 to 800
    const clampedLon = Math.max(-180, Math.min(180, lon));
    const clampedLat = Math.max(-90, Math.min(90, lat));
    const x = ((clampedLon + 180) / 360) * mapWidth;
    // y ranges from 90 to -90 -> 0 to 400
    const y = ((90 - clampedLat) / 180) * mapHeight;
    return { x, y };
  };

  return (
    <Card
      title="OBSERVED IP INFRASTRUCTURE GEOLOCATION"
      subtitle="Approximate geographic coordinates of relay and hosted infrastructure nodes"
      icon={<Globe className="w-4 h-4 text-cyber-cyan" />}
      className={className}
    >
      <div className="space-y-4">
        
        {/* Attribution Guard Notice */}
        <div className="p-3 rounded-lg bg-cyan-950/30 border border-cyan-500/30 flex items-center justify-between text-xs font-mono">
          <div className="flex items-center space-x-2 text-cyan-300">
            <Info className="w-4 h-4 text-cyber-cyan shrink-0" />
            <span>METRIC: Approximate IP infrastructure location (GeoIP database resolution)</span>
          </div>
          <span className="text-[11px] text-slate-400">
            {geoIps.length} Plotted Node{geoIps.length !== 1 ? 's' : ''}
          </span>
        </div>

        {/* Map Canvas / SVG Container */}
        <div className="relative w-full h-72 sm:h-96 rounded-xl bg-cyber-surface border border-cyber-border overflow-hidden flex items-center justify-center">
          
          {/* Cyber Grid Background */}
          <div className="absolute inset-0 bg-cyber-grid bg-[size:24px_24px] opacity-40" />

          {/* SVG World Map Outline & Grid Lines */}
          <svg
            viewBox={`0 0 ${mapWidth} ${mapHeight}`}
            className="w-full h-full object-contain select-none"
          >
            <defs>
              <radialGradient id="cyberGlow" cx="50%" cy="50%" r="50%">
                <stop offset="0%" stopColor="#00f0ff" stopOpacity="0.8" />
                <stop offset="100%" stopColor="#00f0ff" stopOpacity="0" />
              </radialGradient>
            </defs>

            {/* Latitude / Longitude Guide Lines */}
            {[100, 200, 300].map((y) => (
              <line
                key={`lat-${y}`}
                x1="0"
                y1={y}
                x2={mapWidth}
                y2={y}
                stroke="#1e293b"
                strokeWidth="1"
                strokeDasharray="4 4"
              />
            ))}
            {[200, 400, 600].map((x) => (
              <line
                key={`lon-${x}`}
                x1={x}
                y1="0"
                x2={x}
                y2={mapHeight}
                stroke="#1e293b"
                strokeWidth="1"
                strokeDasharray="4 4"
              />
            ))}

            {/* World Landmass Simplified Polygons */}
            {/* North America */}
            <path
              d="M 120 70 L 220 60 L 270 90 L 240 180 L 190 220 L 170 200 L 120 120 Z"
              fill="#131c2e"
              stroke="#1e2d4a"
              strokeWidth="1"
            />
            {/* South America */}
            <path
              d="M 230 220 L 280 240 L 310 300 L 260 370 L 230 310 Z"
              fill="#131c2e"
              stroke="#1e2d4a"
              strokeWidth="1"
            />
            {/* Europe */}
            <path
              d="M 400 80 L 460 70 L 480 110 L 430 140 L 390 120 Z"
              fill="#131c2e"
              stroke="#1e2d4a"
              strokeWidth="1"
            />
            {/* Africa */}
            <path
              d="M 390 145 L 480 140 L 510 220 L 460 310 L 410 270 L 380 180 Z"
              fill="#131c2e"
              stroke="#1e2d4a"
              strokeWidth="1"
            />
            {/* Asia */}
            <path
              d="M 480 70 L 680 70 L 720 140 L 650 200 L 580 190 L 540 130 Z"
              fill="#131c2e"
              stroke="#1e2d4a"
              strokeWidth="1"
            />
            {/* Australia */}
            <path
              d="M 640 270 L 730 270 L 720 340 L 650 340 Z"
              fill="#131c2e"
              stroke="#1e2d4a"
              strokeWidth="1"
            />

            {/* Plotted IP Nodes */}
            {geoIps.map((node, i) => {
              const { x, y } = projectCoord(node.geo.latitude!, node.geo.longitude!);
              const isHovered = hoveredIp?.ip === node.ip;

              return (
                <g
                  key={`marker-${node.ip || i}-${i}`}
                  className="cursor-pointer transition-transform"
                  onMouseEnter={() => setHoveredIp(node)}
                  onMouseLeave={() => setHoveredIp(null)}
                >
                  {/* Ping Animation Wave */}
                  <circle
                    cx={x}
                    cy={y}
                    r={isHovered ? 14 : 8}
                    fill="none"
                    stroke="#00f0ff"
                    strokeWidth="1.5"
                    className="animate-ping origin-center opacity-75"
                  />

                  {/* Node Center Dot */}
                  <circle
                    cx={x}
                    cy={y}
                    r={isHovered ? 5 : 3.5}
                    fill="#00f0ff"
                    stroke="#080c14"
                    strokeWidth="1.5"
                    className="shadow-[0_0_10px_#00f0ff]"
                  />

                  {/* Label Text */}
                  <text
                    x={x + 8}
                    y={y + 3}
                    fill="#f1f5f9"
                    fontSize="9"
                    fontFamily="monospace"
                    fontWeight="bold"
                    className="pointer-events-none drop-shadow-md"
                  >
                    {node.geo.city || node.geo.country_code || node.ip}
                  </text>
                </g>
              );
            })}
          </svg>

          {/* Empty State Overlay */}
          {geoIps.length === 0 && (
            <div className="absolute inset-0 flex flex-col items-center justify-center p-6 text-center bg-cyber-bg/70 backdrop-blur-xs">
              <Compass className="w-8 h-8 text-slate-500 mb-2" />
              <span className="font-mono text-xs font-bold text-slate-300">
                NO GEOLOCATED INFRASTRUCTURE NODES
              </span>
              <p className="text-[11px] text-slate-500 max-w-sm mt-1">
                Extracted IPs are either private (RFC 1918), unroutable, or not present in the local MaxMind database.
              </p>
            </div>
          )}

          {/* Hover Tooltip Overlay */}
          {hoveredIp && (
            <div className="absolute bottom-4 left-4 p-3 rounded-lg bg-slate-900/90 border border-cyber-cyan shadow-xl backdrop-blur-md text-xs font-mono space-y-1 animate-fadeIn z-20">
              <div className="flex items-center space-x-2 text-cyan-400 font-bold">
                <MapPin className="w-3.5 h-3.5" />
                <span>{hoveredIp.ip}</span>
              </div>
              <div className="text-slate-300 text-[11px]">
                {hoveredIp.geo?.city ? `${hoveredIp.geo.city}, ` : ''}
                {hoveredIp.geo?.region ? `${hoveredIp.geo.region}, ` : ''}
                {hoveredIp.geo?.country || 'UNAVAILABLE'} ({hoveredIp.geo?.country_code || '--'})
              </div>
              {hoveredIp.asn?.organization && (
                <div className="text-slate-400 text-[10px]">
                  ASN: {hoveredIp.asn.asn} ({hoveredIp.asn.organization})
                </div>
              )}
              {typeof hoveredIp.geo?.latitude === 'number' && typeof hoveredIp.geo?.longitude === 'number' && (
                <div className="text-[9px] text-slate-500">
                  Coords: {hoveredIp.geo.latitude.toFixed(4)}, {hoveredIp.geo.longitude.toFixed(4)}
                </div>
              )}
            </div>
          )}

        </div>

      </div>
    </Card>
  );
};
