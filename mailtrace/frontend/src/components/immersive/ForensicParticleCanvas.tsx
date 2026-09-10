import React, { useEffect, useRef } from 'react';

interface ForensicParticleCanvasProps {
  stage?: number; // 1: detect, 2: trace, 3: investigate, 4: evidence
  intensity?: number;
}

export const ForensicParticleCanvas: React.FC<ForensicParticleCanvasProps> = ({
  stage = 1,
  intensity = 1.0,
}) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let width = (canvas.width = canvas.parentElement?.clientWidth || window.innerWidth);
    let height = (canvas.height = canvas.parentElement?.clientHeight || window.innerHeight);

    const handleResize = () => {
      if (!canvas || !canvas.parentElement) return;
      width = canvas.width = canvas.parentElement.clientWidth;
      height = canvas.height = canvas.parentElement.clientHeight;
    };

    window.addEventListener('resize', handleResize);

    // Particle nodes
    const nodeCount = Math.min(65, Math.floor((width * height) / 18000));
    interface Node {
      x: number;
      y: number;
      vx: number;
      vy: number;
      size: number;
      color: string;
      isThreat?: boolean;
      pulsePhase: number;
    }

    const stageColors = {
      1: { primary: 'rgba(6, 182, 212, ', threat: 'rgba(244, 63, 94, ' }, // cyan & rose (detect)
      2: { primary: 'rgba(59, 130, 246, ', threat: 'rgba(249, 115, 22, ' }, // blue & orange (trace)
      3: { primary: 'rgba(139, 92, 246, ', threat: 'rgba(239, 68, 68, ' }, // violet & red (investigate)
      4: { primary: 'rgba(16, 185, 129, ', threat: 'rgba(6, 182, 212, ' }, // emerald & cyan (evidence)
    };

    const currentPalette = stageColors[stage as keyof typeof stageColors] || stageColors[1];

    const nodes: Node[] = [];
    for (let i = 0; i < nodeCount; i++) {
      const isThreat = Math.random() < 0.25;
      nodes.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.6 * intensity,
        vy: (Math.random() - 0.5) * 0.6 * intensity,
        size: Math.random() * 2.2 + 1.2,
        color: isThreat ? currentPalette.threat : currentPalette.primary,
        isThreat,
        pulsePhase: Math.random() * Math.PI * 2,
      });
    }

    // Packet pulses travelling along connections
    interface Packet {
      fromIdx: number;
      toIdx: number;
      progress: number;
      speed: number;
      color: string;
    }
    const packets: Packet[] = [];

    const createPacket = () => {
      if (nodes.length < 2) return;
      const fromIdx = Math.floor(Math.random() * nodes.length);
      let toIdx = Math.floor(Math.random() * nodes.length);
      while (toIdx === fromIdx) {
        toIdx = Math.floor(Math.random() * nodes.length);
      }
      packets.push({
        fromIdx,
        toIdx,
        progress: 0,
        speed: 0.008 + Math.random() * 0.012,
        color: nodes[fromIdx].isThreat ? currentPalette.threat : currentPalette.primary,
      });
    };

    let tick = 0;

    const render = () => {
      tick++;
      ctx.clearRect(0, 0, width, height);

      // Cyber grid background
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.018)';
      ctx.lineWidth = 1;
      const gridSize = 48;
      for (let x = 0; x < width; x += gridSize) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
        ctx.stroke();
      }
      for (let y = 0; y < height; y += gridSize) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
      }

      // Update and draw node connections
      const maxDistance = 140;
      for (let i = 0; i < nodes.length; i++) {
        const a = nodes[i];
        for (let j = i + 1; j < nodes.length; j++) {
          const b = nodes[j];
          const dx = a.x - b.x;
          const dy = a.y - b.y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < maxDistance) {
            const alpha = (1 - dist / maxDistance) * 0.22;
            ctx.beginPath();
            ctx.strokeStyle = a.isThreat || b.isThreat 
              ? `${currentPalette.threat}${alpha * 1.2})` 
              : `${currentPalette.primary}${alpha})`;
            ctx.lineWidth = a.isThreat && b.isThreat ? 1.4 : 0.8;
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.stroke();
          }
        }
      }

      // Spawn packet bursts periodically
      if (tick % 45 === 0 && packets.length < 12) {
        createPacket();
      }

      // Render packet flows
      for (let p = packets.length - 1; p >= 0; p--) {
        const pkt = packets[p];
        pkt.progress += pkt.speed;

        const from = nodes[pkt.fromIdx];
        const to = nodes[pkt.toIdx];

        if (from && to) {
          const curX = from.x + (to.x - from.x) * pkt.progress;
          const curY = from.y + (to.y - from.y) * pkt.progress;

          ctx.beginPath();
          ctx.arc(curX, curY, 2.5, 0, Math.PI * 2);
          ctx.fillStyle = `${pkt.color}0.9)`;
          ctx.shadowColor = `${pkt.color}1)`;
          ctx.shadowBlur = 8;
          ctx.fill();
          ctx.shadowBlur = 0;
        }

        if (pkt.progress >= 1) {
          packets.splice(p, 1);
        }
      }

      // Update and draw nodes
      for (let i = 0; i < nodes.length; i++) {
        const n = nodes[i];
        n.x += n.vx;
        n.y += n.vy;

        // Bounce
        if (n.x < 0 || n.x > width) n.vx *= -1;
        if (n.y < 0 || n.y > height) n.vy *= -1;

        n.pulsePhase += 0.03;
        const pulse = Math.sin(n.pulsePhase) * 0.35 + 1;

        ctx.beginPath();
        ctx.arc(n.x, n.y, n.size * pulse, 0, Math.PI * 2);
        ctx.fillStyle = `${n.color}0.85)`;
        ctx.shadowColor = `${n.color}0.7)`;
        ctx.shadowBlur = n.isThreat ? 12 : 6;
        ctx.fill();
        ctx.shadowBlur = 0;
      }

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      window.removeEventListener('resize', handleResize);
      cancelAnimationFrame(animationFrameId);
    };
  }, [stage, intensity]);

  return (
    <canvas
      ref={canvasRef}
      className="pointer-events-none absolute inset-0 h-full w-full opacity-70"
      style={{ mixBlendMode: 'screen' }}
    />
  );
};
