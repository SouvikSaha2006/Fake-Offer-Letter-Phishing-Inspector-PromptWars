import React, { useState } from 'react';
import { ShieldCheck, ShieldAlert, AlertCircle, Terminal, Search, Lock } from 'lucide-react';
import Header from './components/Header';
import ScannerInput from './components/ScannerInput';
import ThreatGauge from './components/ThreatGauge';
import FlagBadges from './components/FlagBadges';
import Remediation from './components/Remediation';
import { TEST_SCENARIOS } from './data/sampleScenarios';

export default function App() {
  const [text, setText] = useState('');
  const [url, setUrl] = useState('');
  const [selectedScenarioId, setSelectedScenarioId] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [scanError, setScanError] = useState(null);
  const [latencyMs, setLatencyMs] = useState(null);

  // Handle scenario selection from header dropdown
  const handleSelectScenario = (scenarioId) => {
    setSelectedScenarioId(scenarioId);
    const scenario = TEST_SCENARIOS.find((s) => s.id === scenarioId);
    if (scenario) {
      if (scenario.type === 'text') {
        setText(scenario.content);
        setUrl('');
      } else {
        setUrl(scenario.content);
        setText('');
      }
      setScanResult(null);
      setScanError(null);
    }
  };

  // Clear inputs and current scan report
  const handleClear = () => {
    setText('');
    setUrl('');
    setSelectedScenarioId('');
    setScanResult(null);
    setScanError(null);
    setLatencyMs(null);
  };

  // Execute scan API request
  const handleRunScan = async () => {
    const rawText = text.trim();
    const rawUrl = url.trim();

    if (!rawText && !rawUrl) {
      setScanError('Please enter offer letter text or a target URL to scan.');
      return;
    }

    setIsScanning(true);
    setScanError(null);
    const startTime = performance.now();

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          text: rawText,
          url: rawUrl
        })
      });

      const elapsed = Math.round(performance.now() - startTime);
      setLatencyMs(elapsed);

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.error || `Server returned HTTP ${response.status}`);
      }

      const data = await response.json();
      setScanResult(data);
    } catch (err) {
      console.error('[Scan Execution Error]:', err);
      setScanError(err.message || 'Failed to connect to PhishGuard backend engine.');
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#090d16] text-slate-100 flex flex-col selection:bg-emerald-500/30 selection:text-emerald-200">
      {/* Top Banner & Header */}
      <Header
        onSelectScenario={handleSelectScenario}
        selectedScenarioId={selectedScenarioId}
        latencyMs={latencyMs}
      />

      {/* Main Forensic Workspace */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        
        {/* Error Notification Banner */}
        {scanError && (
          <div 
            role="alert"
            className="mb-6 p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 flex items-start gap-3 shadow-lg animate-fadeIn"
          >
            <AlertCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
            <div className="flex-1 text-xs leading-relaxed">
              <strong className="font-semibold text-rose-200 block mb-0.5">Scan Execution Error</strong>
              <span>{scanError}</span>
            </div>
            <button
              onClick={() => setScanError(null)}
              className="text-xs text-rose-400 hover:text-rose-200 underline font-mono"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Dual-Pane Layout */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          
          {/* Left Pane: Ingestion Console (5 Cols) */}
          <div className="lg:col-span-5 h-full">
            <ScannerInput
              text={text}
              setText={setText}
              url={url}
              setUrl={setUrl}
              onScan={handleRunScan}
              isScanning={isScanning}
              onClear={handleClear}
            />
          </div>

          {/* Right Pane: Forensic Intelligence Console (7 Cols) */}
          <section 
            aria-labelledby="results-heading"
            aria-live="polite"
            className="lg:col-span-7 space-y-6"
          >
            <h2 id="results-heading" className="sr-only">
              Forensic Intelligence Console
            </h2>

            {/* State 1: Scanning / Skeleton Loading */}
            {isScanning && (
              <div className="space-y-6 animate-pulse" aria-label="Analyzing payload...">
                {/* Gauge Skeleton */}
                <div className="bg-[#0f172a] rounded-xl border border-slate-800 p-6 flex flex-col items-center gap-4">
                  <div className="w-36 h-36 rounded-full border-4 border-slate-800 border-t-emerald-500 animate-spin flex items-center justify-center">
                    <Terminal className="w-8 h-8 text-slate-700" />
                  </div>
                  <div className="h-4 w-48 bg-slate-800 rounded"></div>
                  <div className="w-full space-y-2 pt-4 border-t border-slate-800">
                    <div className="h-2 w-full bg-slate-800 rounded"></div>
                    <div className="h-2 w-full bg-slate-800 rounded"></div>
                  </div>
                </div>

                {/* Findings Matrix Skeleton */}
                <div className="bg-[#0f172a] rounded-xl border border-slate-800 p-6 space-y-3">
                  <div className="h-4 w-40 bg-slate-800 rounded mb-4"></div>
                  <div className="h-16 w-full bg-slate-800/60 rounded-lg"></div>
                  <div className="h-16 w-full bg-slate-800/60 rounded-lg"></div>
                </div>
              </div>
            )}

            {/* State 2: Active Diagnostic Report */}
            {!isScanning && scanResult && (
              <div className="space-y-6 animate-fadeIn">
                {/* Hero Radial Threat Gauge */}
                <ThreatGauge
                  score={scanResult.scamThreatIndex}
                  riskCategory={scanResult.riskCategory}
                  breakdown={scanResult.breakdown}
                />

                {/* Forensic Findings Matrix */}
                <FlagBadges
                  findings={scanResult.itemizedEvidence || []}
                  domainDetails={scanResult.domains?.domainDetails || []}
                />

                {/* Remediation & Countermeasure Playbook */}
                <Remediation
                  advice={scanResult.remediationAdvice || []}
                  fullAuditData={scanResult}
                />
              </div>
            )}

            {/* State 3: Empty State Placeholder */}
            {!isScanning && !scanResult && (
              <div className="bg-[#0f172a] rounded-xl border border-slate-800/90 p-8 shadow-xl flex flex-col items-center justify-center text-center min-h-[460px]">
                <div className="w-16 h-16 rounded-2xl bg-slate-800/60 border border-slate-700/60 flex items-center justify-center mb-4 text-slate-500">
                  <Lock className="w-8 h-8 text-slate-400" />
                </div>

                <h3 className="text-sm font-semibold tracking-wide uppercase text-slate-300 mb-2">
                  Awaiting Payload Ingestion
                </h3>

                <p className="text-xs text-slate-400 max-w-md leading-relaxed mb-6">
                  Paste an offer letter, recruitment message, or rental contract into the left console, or load a pre-configured scenario from the top menu to execute the multi-layered forensic engine.
                </p>

                <div className="flex flex-wrap items-center justify-center gap-2 text-[11px] font-mono text-slate-400">
                  <span className="px-2.5 py-1 rounded bg-slate-800/60 border border-slate-700/50">
                    RDAP AUTHORITY
                  </span>
                  <span className="px-2.5 py-1 rounded bg-slate-800/60 border border-slate-700/50">
                    HEURISTIC SCANNERS
                  </span>
                  <span className="px-2.5 py-1 rounded bg-slate-800/60 border border-slate-700/50">
                    GEMINI SEMANTICS
                  </span>
                </div>
              </div>
            )}

          </section>

        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-[#090d16] py-4 text-center text-xs font-mono text-slate-400">
        <span>PHISHGUARD FORENSIC OS // TOPIC 1 INSPECTOR // ZERO HALLUCINATION SEC-ENGINE</span>
      </footer>
    </div>
  );
}
