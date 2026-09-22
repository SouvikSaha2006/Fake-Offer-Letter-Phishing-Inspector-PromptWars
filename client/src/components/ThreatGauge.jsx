import React from 'react';
import { ShieldCheck, AlertTriangle, ShieldAlert } from 'lucide-react';

export default function ThreatGauge({ score = 0, riskCategory = 'AUTHENTIC', breakdown = {} }) {
  const normalizedScore = Math.max(0, Math.min(100, Math.round(score)));

  // SVG circular geometry parameters
  const radius = 68;
  const strokeWidth = 10;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (normalizedScore / 100) * circumference;

  // Semantic color and badge mapping based on score
  let strokeColor = '#10b981'; // Emerald (< 30)
  let glowColor = 'rgba(16, 185, 129, 0.2)';
  let textColor = 'text-emerald-400';
  let badgeBg = 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400';
  let badgeLabel = 'AUTHENTIC OPPORTUNITY';
  let Icon = ShieldCheck;

  if (normalizedScore >= 70 || riskCategory === 'CRITICAL FRAUD') {
    strokeColor = '#f43f5e'; // Rose (>= 70)
    glowColor = 'rgba(244, 63, 94, 0.25)';
    textColor = 'text-rose-400';
    badgeBg = 'bg-rose-500/10 border-rose-500/30 text-rose-400';
    badgeLabel = 'CRITICAL FRAUD CONFIRMED';
    Icon = ShieldAlert;
  } else if (normalizedScore >= 30 || riskCategory === 'SUSPICIOUS') {
    strokeColor = '#f59e0b'; // Amber (30–69)
    glowColor = 'rgba(245, 158, 11, 0.2)';
    textColor = 'text-amber-400';
    badgeBg = 'bg-amber-500/10 border-amber-500/30 text-amber-400';
    badgeLabel = 'SUSPICIOUS ACTIVITY';
    Icon = AlertTriangle;
  }

  // Sub-scores extraction
  const domainRisk = breakdown.domainRisk ?? 0;
  const paymentRisk = breakdown.paymentRisk ?? 0;
  const proceduralRisk = breakdown.proceduralRisk ?? 0;
  const geminiRisk = breakdown.geminiRisk ?? 0;

  return (
    <div 
      data-testid="threat-score-gauge"
      className="bg-[#0f172a] rounded-xl border border-slate-800/90 p-5 shadow-xl flex flex-col items-center"
    >
      {/* Top Header */}
      <div className="w-full flex items-center justify-between border-b border-slate-800/80 pb-3 mb-4">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
          Forensic Threat Assessment
        </span>
        <span className="text-[11px] font-mono text-slate-400 bg-slate-800/60 px-2 py-0.5 rounded border border-slate-700/60">
          MODEL: S-INDEX v1.0
        </span>
      </div>

      {/* Radial Gauge Visual */}
      <div className="relative flex items-center justify-center my-2">
        <svg 
          width="170" 
          height="170" 
          className="transform -rotate-90 drop-shadow-md"
          aria-hidden="true"
        >
          {/* Background Track */}
          <circle
            cx="85"
            cy="85"
            r={radius}
            stroke="#1e293b"
            strokeWidth={strokeWidth}
            fill="transparent"
          />
          {/* Active Animated Progress Arc */}
          <circle
            cx="85"
            cy="85"
            r={radius}
            stroke={strokeColor}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            fill="transparent"
            style={{
              transition: 'stroke-dashoffset 0.8s cubic-bezier(0.4, 0, 0.2, 1), stroke 0.4s ease',
              filter: `drop-shadow(0 0 8px ${glowColor})`
            }}
          />
        </svg>

        {/* Center Numerical Score & Status Icon */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <Icon className={`w-5 h-5 mb-0.5 ${textColor}`} />
          <span className={`text-4xl font-bold font-mono tracking-tight tabular-nums ${textColor}`}>
            {normalizedScore}%
          </span>
          <span className="text-[10px] font-mono uppercase text-slate-400 tracking-wider">
            Threat Index
          </span>
        </div>
      </div>

      {/* Status Badge */}
      <div className={`mt-2 px-3 py-1 rounded-full border text-xs font-bold font-mono tracking-wide flex items-center gap-1.5 ${badgeBg}`}>
        <span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse"></span>
        <span>{badgeLabel}</span>
      </div>

      {/* Sub-Score Breakdown Bars with Semantic Definition List (dl/dt/dd) */}
      <dl className="w-full mt-6 space-y-3 pt-4 border-t border-slate-800/80">
        <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-2">
          Composite Factor Decomposition
        </div>

        {/* 1. Domain Risk (30%) */}
        <div>
          <div className="flex justify-between text-xs font-mono mb-1">
            <dt className="text-slate-400">Domain Authority & Age (30%)</dt>
            <dd className="text-slate-200 font-semibold tabular-nums">{domainRisk}/100</dd>
          </div>
          <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
            <div 
              className="h-full bg-gradient-to-r from-sky-500 to-indigo-500 transition-all duration-700" 
              style={{ width: `${domainRisk}%` }}
            />
          </div>
        </div>

        {/* 2. Payment Flags (30%) */}
        <div>
          <div className="flex justify-between text-xs font-mono mb-1">
            <dt className="text-slate-400">Payment & Deposit Demands (30%)</dt>
            <dd className="text-slate-200 font-semibold tabular-nums">{paymentRisk}/100</dd>
          </div>
          <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
            <div 
              className="h-full bg-gradient-to-r from-rose-500 to-amber-500 transition-all duration-700" 
              style={{ width: `${paymentRisk}%` }}
            />
          </div>
        </div>

        {/* 3. Recruitment Integrity (20%) */}
        <div>
          <div className="flex justify-between text-xs font-mono mb-1">
            <dt className="text-slate-400">Recruitment Channel Integrity (20%)</dt>
            <dd className="text-slate-200 font-semibold tabular-nums">{proceduralRisk}/100</dd>
          </div>
          <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
            <div 
              className="h-full bg-gradient-to-r from-amber-500 to-yellow-500 transition-all duration-700" 
              style={{ width: `${proceduralRisk}%` }}
            />
          </div>
        </div>

        {/* 4. Semantic Deception (20%) */}
        <div>
          <div className="flex justify-between text-xs font-mono mb-1">
            <dt className="text-slate-400">Semantic & Cognitive Deception (20%)</dt>
            <dd className="text-slate-200 font-semibold tabular-nums">{geminiRisk}/100</dd>
          </div>
          <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
            <div 
              className="h-full bg-gradient-to-r from-emerald-500 to-cyan-500 transition-all duration-700" 
              style={{ width: `${geminiRisk}%` }}
            />
          </div>
        </div>
      </dl>
    </div>
  );
}
