import React from 'react';
import { ShieldAlert, Activity, Cpu, Clock, ChevronDown } from 'lucide-react';
import { TEST_SCENARIOS } from '../data/sampleScenarios';

export default function Header({ onSelectScenario, selectedScenarioId, latencyMs }) {
  const latencyDisplay = latencyMs 
    ? `${(latencyMs / 1000).toFixed(2)}s` 
    : '< 1.4s';

  return (
    <header 
      role="banner" 
      className="border-b border-slate-800/80 bg-[#090d16]/90 backdrop-blur-md sticky top-0 z-50 px-4 lg:px-8 py-3.5"
    >
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-3 md:gap-6">
        
        {/* Left: Brand Lockup */}
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-9 h-9 rounded-lg bg-gradient-to-br from-emerald-500/20 to-sky-500/20 border border-emerald-500/30 text-emerald-400 shadow-[0_0_15px_rgba(16,185,129,0.15)]">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold tracking-wider text-slate-100 uppercase">
                PhishGuard <span className="text-emerald-400 font-mono">//</span> <span className="text-slate-400 font-medium">INSPECTOR</span>
              </h1>
              <span className="text-[10px] font-mono font-medium px-2 py-0.5 rounded bg-slate-800/90 text-sky-400 border border-slate-700/60 tracking-tight">
                v1.2.0-cloudrun
              </span>
            </div>
            <p className="text-xs text-slate-400 hidden sm:block">
              Forensic Offer Letter & Phishing Intelligence Engine
            </p>
          </div>
        </div>

        {/* Center: System Telemetry Pills */}
        <div className="hidden lg:flex items-center gap-2 font-mono text-[11px] text-slate-300">
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-slate-900 border border-slate-800">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <span className="text-slate-400">API:</span>
            <span className="text-emerald-400 font-semibold">READY</span>
          </div>

          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-slate-900 border border-slate-800 text-slate-400">
            <Cpu className="w-3.5 h-3.5 text-sky-400" />
            <span>ENGINE:</span>
            <span className="text-sky-300">RDAP + GEMINI-1.5-FLASH</span>
          </div>

          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-slate-900 border border-slate-800 text-slate-400">
            <Clock className="w-3.5 h-3.5 text-amber-400" />
            <span>LATENCY:</span>
            <span className="text-amber-300 tabular-nums">{latencyDisplay}</span>
          </div>
        </div>

        {/* Right: Load Test Scenario Selector */}
        <div className="w-full md:w-auto flex items-center justify-end gap-2">
          <label htmlFor="scenario-select" className="sr-only">
            Load Test Scenario
          </label>
          <div className="relative w-full md:w-72">
            <select
              id="scenario-select"
              data-testid="sample-selector"
              aria-label="Load Test Scenario"
              value={selectedScenarioId || ''}
              onChange={(e) => onSelectScenario(e.target.value)}
              className="w-full appearance-none bg-slate-900/90 text-slate-200 border border-slate-700/80 rounded-lg px-3 py-2 text-xs font-medium focus:outline-none focus:ring-2 focus:ring-emerald-500/40 focus:border-emerald-500 transition-colors pr-8 cursor-pointer hover:border-slate-600"
            >
              <option value="" disabled>
                -- Load Test Scenario --
              </option>
              {TEST_SCENARIOS.map((s) => (
                <option key={s.id} value={s.id}>
                  [{s.badge}] {s.name}
                </option>
              ))}
            </select>
            <ChevronDown className="w-4 h-4 text-slate-400 absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
          </div>
        </div>

      </div>
    </header>
  );
}
