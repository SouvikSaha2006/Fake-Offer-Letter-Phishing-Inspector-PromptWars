import React, { useState } from 'react';
import { ShieldAlert, AlertCircle, Terminal, Lock } from 'lucide-react';
import Header from './components/Header';
import ScannerInput from './components/ScannerInput';
import ThreatGauge from './components/ThreatGauge';
import FlagBadges from './components/FlagBadges';
import Remediation from './components/Remediation';
import { TEST_SCENARIOS } from './data/sampleScenarios';

export default function App() {
  const [activeTab, setActiveTab] = useState('text'); // 'text' | 'url'
  const [text, setText] = useState('');
  const [url, setUrl] = useState('');
  const [selectedScenarioId, setSelectedScenarioId] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanError, setScanError] = useState(null);
  const [latencyMs, setLatencyMs] = useState(null);

  // Dedicated, explicit state variables directly updated from API
  const [threatScore, setThreatScore] = useState(null);
  const [riskCategory, setRiskCategory] = useState('AUTHENTIC');
  const [factorDecomposition, setFactorDecomposition] = useState({
    domainRisk: 0,
    paymentRisk: 0,
    proceduralRisk: 0,
    semanticRisk: 0
  });
  const [findings, setFindings] = useState([]);
  const [remediation, setRemediation] = useState([]);
  const [domainDetails, setDomainDetails] = useState([]);
  const [rawAuditData, setRawAuditData] = useState(null);

  // Handle scenario selection from header dropdown
  const handleSelectScenario = (scenarioId) => {
    setSelectedScenarioId(scenarioId);
    const scenario = TEST_SCENARIOS.find((s) => s.id === scenarioId);
    if (scenario) {
      if (scenario.type === 'url') {
        setActiveTab('url');
        setUrl(scenario.content);
        setText('');
      } else {
        setActiveTab('text');
        setText(scenario.content);
        setUrl('');
      }
      // Clear stale scan state
      setThreatScore(null);
      setFindings([]);
      setRemediation([]);
      setRawAuditData(null);
      setScanError(null);
      setLatencyMs(null);
    }
  };

  // Clear inputs and current scan report
  const handleClear = () => {
    setText('');
    setUrl('');
    setSelectedScenarioId('');
    setThreatScore(null);
    setRiskCategory('AUTHENTIC');
    setFactorDecomposition({
      domainRisk: 0,
      paymentRisk: 0,
      proceduralRisk: 0,
      semanticRisk: 0
    });
    setFindings([]);
    setRemediation([]);
    setDomainDetails([]);
    setRawAuditData(null);
    setScanError(null);
    setLatencyMs(null);
  };

  // Execute scan API request reading live, updated state
  const handleRunScan = async (currentTab = activeTab) => {
    const rawText = text.trim();
    const targetUrl = url.trim();

    // Verify input presence based on active tab
    if (currentTab === 'text' && !rawText) {
      setScanError('Please enter offer letter or message text to analyze.');
      return;
    }
    if (currentTab === 'url' && !targetUrl) {
      setScanError('Please enter a valid target URL to inspect.');
      return;
    }

    setIsScanning(true);
    setScanError(null);
    const startTime = performance.now();

    // Explicit payload format: sends text if on text tab, url if on url tab
    const payload = {
      text: currentTab === 'text' ? rawText : '',
      url: currentTab === 'url' ? targetUrl : ''
    };

    console.log('[CLIENT SCAN] Dispatching live payload:', {
      activeTab: currentTab,
      textLength: payload.text.length,
      url: payload.url
    });

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      });

      const elapsed = Math.round(performance.now() - startTime);
      setLatencyMs(elapsed);

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.error || `Server returned HTTP ${response.status}`);
      }

      const data = await response.json();
      console.log('[CLIENT SCAN] Received forensic report:', data);

      // Directly update all state variables with live API response
      const score = typeof data.threatScore === 'number' 
        ? data.threatScore 
        : (data.scamThreatIndex ?? 0);

      const category = data.category || data.riskCategory || 'AUTHENTIC';

      const decomposition = {
        domainRisk: data.metrics?.domainRisk ?? data.breakdown?.domainRisk ?? 0,
        paymentRisk: data.metrics?.paymentRisk ?? data.breakdown?.paymentRisk ?? 0,
        proceduralRisk: data.metrics?.proceduralRisk ?? data.breakdown?.proceduralRisk ?? 0,
        semanticRisk: data.metrics?.semanticRisk ?? data.breakdown?.semanticRisk ?? data.breakdown?.geminiRisk ?? 0
      };

      const findingsList = data.findings || data.itemizedEvidence || [];
      const remediationList = data.remediation || data.remediationAdvice || [];
      const domains = data.details?.domains?.domainDetails || data.domains?.domainDetails || [];

      setThreatScore(score);
      setRiskCategory(category);
      setFactorDecomposition(decomposition);
      setFindings(findingsList);
      setRemediation(remediationList);
      setDomainDetails(domains);
      setRawAuditData(data);

    } catch (err) {
      console.error('[Scan Execution Error]:', err);
      setScanError(err.message || 'Failed to connect to PhishGuard backend engine.');
    } finally {
      setIsScanning(false);
    }
  };

  const hasReport = threatScore !== null;

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
            className="mb-6 p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 flex items-start gap-3 shadow-lg"
          >
            <AlertCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
            <div className="flex-1 text-xs leading-relaxed">
              <strong className="font-semibold text-rose-200 block mb-0.5">Scan Execution Error</strong>
              <span>{scanError}</span>
            </div>
            <button
              onClick={() => setScanError(null)}
              className="text-xs text-rose-400 hover:text-rose-200 underline font-mono focus:outline-none focus:ring-2 focus:ring-rose-500/50"
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
              activeTab={activeTab}
              setActiveTab={setActiveTab}
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
            {!isScanning && hasReport && (
              <div className="space-y-6">
                {/* Hero Radial Threat Gauge */}
                <ThreatGauge
                  score={threatScore}
                  riskCategory={riskCategory}
                  factorDecomposition={factorDecomposition}
                  breakdown={factorDecomposition}
                />

                {/* Forensic Findings Matrix */}
                <FlagBadges
                  findings={findings}
                  domainDetails={domainDetails}
                />

                {/* Remediation & Countermeasure Playbook */}
                <Remediation
                  advice={remediation}
                  fullAuditData={rawAuditData}
                />
              </div>
            )}

            {/* State 3: Empty State Placeholder */}
            {!isScanning && !hasReport && (
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
