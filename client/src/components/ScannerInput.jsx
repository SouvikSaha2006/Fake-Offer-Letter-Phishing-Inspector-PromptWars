import React, { useState } from 'react';
import { FileText, Globe, Play, Trash2, Loader2, Sparkles, AlertCircle } from 'lucide-react';

export default function ScannerInput({ 
  text, 
  setText, 
  url, 
  setUrl, 
  onScan, 
  isScanning, 
  onClear 
}) {
  const [activeTab, setActiveTab] = useState('text'); // 'text' | 'url'

  const wordCount = text.trim() ? text.trim().split(/\s+/).length : 0;
  const charCount = text.length;

  const handleSubmit = (e) => {
    e.preventDefault();
    if (isScanning) return;
    onScan();
  };

  const hasContent = activeTab === 'text' ? text.trim().length > 0 : url.trim().length > 0;

  return (
    <section 
      aria-labelledby="input-heading"
      className="bg-[#0f172a] rounded-xl border border-slate-800/90 shadow-xl overflow-hidden flex flex-col h-full"
    >
      {/* Pane Header & Tabs */}
      <div className="border-b border-slate-800/80 px-4 py-3 flex items-center justify-between bg-slate-900/60">
        <div className="flex items-center gap-2">
          <h2 id="input-heading" className="text-xs font-semibold uppercase tracking-wider text-slate-300">
            Forensic Payload Ingestion
          </h2>
        </div>

        {/* Tab Switcher */}
        <div className="flex items-center gap-1 bg-slate-950/80 p-1 rounded-lg border border-slate-800">
          <button
            type="button"
            onClick={() => setActiveTab('text')}
            className={`flex items-center gap-1.5 px-3 py-1 rounded text-xs font-medium transition-all ${
              activeTab === 'text'
                ? 'bg-slate-800 text-emerald-400 shadow-sm border border-slate-700/60'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Raw Text / Email</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('url')}
            className={`flex items-center gap-1.5 px-3 py-1 rounded text-xs font-medium transition-all ${
              activeTab === 'url'
                ? 'bg-slate-800 text-sky-400 shadow-sm border border-slate-700/60'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Globe className="w-3.5 h-3.5" />
            <span>Target URL</span>
          </button>
        </div>
      </div>

      {/* Input Form */}
      <form onSubmit={handleSubmit} className="flex-1 flex flex-col p-4 gap-3">
        {activeTab === 'text' ? (
          <div className="flex-1 flex flex-col relative min-h-[360px]">
            <label htmlFor="payload-textarea" className="sr-only">
              Offer Letter or Phishing Message Content
            </label>
            <textarea
              id="payload-textarea"
              data-testid="input-textarea"
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder="Paste suspicious offer letter, recruiter email, employment contract, or recruitment chat transcript here..."
              className="flex-1 w-full bg-[#1e293b]/60 text-slate-100 placeholder-slate-500 font-mono text-xs leading-relaxed p-3.5 rounded-lg border border-slate-800 focus:outline-none focus:ring-2 focus:ring-emerald-500/40 focus:border-emerald-500 transition-all resize-none"
              spellCheck="false"
            />
          </div>
        ) : (
          <div className="flex-1 flex flex-col justify-center py-8 px-2 gap-3 min-h-[360px]">
            <label htmlFor="payload-url" className="text-xs font-medium text-slate-300">
              Inspection Target URL or Phishing Landing Page
            </label>
            <div className="relative">
              <Globe className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                id="payload-url"
                type="url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://company-careers-portal-verify.com/jobs/apply"
                className="w-full bg-[#1e293b]/60 text-slate-100 placeholder-slate-500 font-mono text-xs pl-9 pr-3 py-2.5 rounded-lg border border-slate-800 focus:outline-none focus:ring-2 focus:ring-sky-500/40 focus:border-sky-500 transition-all"
              />
            </div>
            <p className="text-[11px] text-slate-400">
              The engine will extract the apex domain, verify registrar authority via ICANN RDAP, and audit domain age.
            </p>
          </div>
        )}

        {/* Action & Counter Toolbar */}
        <div className="pt-2 border-t border-slate-800/80 flex flex-col sm:flex-row items-center justify-between gap-3">
          {/* Counters */}
          <div className="flex items-center gap-4 text-xs font-mono text-slate-400 tabular-nums">
            {activeTab === 'text' ? (
              <>
                <span>
                  Words: <strong className="text-slate-200">{wordCount}</strong>
                </span>
                <span>
                  Characters: <strong className="text-slate-200">{charCount}</strong>
                </span>
              </>
            ) : (
              <span>URL Inspection Mode</span>
            )}
          </div>

          {/* Buttons */}
          <div className="flex items-center gap-2 w-full sm:w-auto justify-end">
            <button
              type="button"
              onClick={onClear}
              disabled={isScanning || (!text && !url)}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 border border-transparent hover:border-rose-500/20 transition-all disabled:opacity-40 disabled:pointer-events-none"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Clear</span>
            </button>

            <button
              type="submit"
              data-testid="scan-button"
              disabled={isScanning || !hasContent}
              className={`flex items-center justify-center gap-2 px-5 py-2 rounded-lg text-xs font-semibold tracking-wide uppercase transition-all shadow-lg ${
                isScanning
                  ? 'bg-emerald-600/50 text-emerald-200 cursor-wait animate-pulse'
                  : hasContent
                  ? 'bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-slate-950 font-bold shadow-emerald-500/20 hover:shadow-emerald-500/30 active:scale-[0.98]'
                  : 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700/60'
              }`}
            >
              {isScanning ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin text-emerald-300" />
                  <span>Executing Forensic Engine...</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Analyze Payload [Run Scan]</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Small Hint Row */}
        <div className="flex items-center gap-1.5 text-[11px] text-slate-400 pt-1">
          <AlertCircle className="w-3.5 h-3.5 text-slate-500 shrink-0" />
          <span>Accepts raw offer letters, recruiter messages, employment contracts, and rental leases.</span>
        </div>
      </form>
    </section>
  );
}
