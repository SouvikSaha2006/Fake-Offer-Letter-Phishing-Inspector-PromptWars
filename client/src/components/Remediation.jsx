import React, { useState } from 'react';
import { ShieldAlert, Check, Copy, ExternalLink, ArrowRight } from 'lucide-react';

export default function Remediation({ advice = [], fullAuditData = null }) {
  const [copied, setCopied] = useState(false);

  const handleCopyAuditLog = async () => {
    if (!fullAuditData) return;
    try {
      await navigator.clipboard.writeText(JSON.stringify(fullAuditData, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy audit log:', err);
    }
  };

  const defaultAdvice = [
    'Do not transfer funds, purchase gift cards, or deposit cashier checks under any circumstances.',
    'Contact the hiring entity via verified contact information found on their public website, never using links inside the message.',
    'Report recruitment impersonation to the FTC (reportfraud.ftc.gov) or IC3 (ic3.gov).'
  ];

  const displayAdvice = advice && advice.length > 0 ? advice : defaultAdvice;

  return (
    <div className="bg-[#0f172a] rounded-xl border border-slate-800/90 p-5 shadow-xl space-y-4">
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-emerald-400" />
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
            Remediation & Countermeasure Playbook
          </h3>
        </div>

        {/* Copy Audit Log Button */}
        {fullAuditData && (
          <button
            type="button"
            onClick={handleCopyAuditLog}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-medium text-slate-300 bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 hover:border-slate-600 transition-all active:scale-95"
          >
            {copied ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-emerald-400">Copied JSON</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5 text-slate-400" />
                <span>Copy Audit Log (JSON)</span>
              </>
            )}
          </button>
        )}
      </div>

      {/* Actionable Checklist */}
      <ul className="space-y-2.5">
        {displayAdvice.map((step, idx) => (
          <li 
            key={idx}
            className="flex items-start gap-3 p-3 rounded-lg bg-[#1e293b]/40 border border-slate-800/80 text-xs text-slate-300 leading-relaxed"
          >
            <div className="flex items-center justify-center w-5 h-5 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-mono text-[10px] shrink-0 mt-0.5 font-bold">
              {idx + 1}
            </div>
            <div className="flex-1">
              <span>{step}</span>
            </div>
          </li>
        ))}
      </ul>

      {/* Official Reporting Footnote */}
      <div className="pt-2 border-t border-slate-800/60 flex items-center justify-between text-[11px] text-slate-400 font-mono">
        <span>IC3.GOV // FTC FRAUD DIVISION</span>
        <a 
          href="https://www.ic3.gov" 
          target="_blank" 
          rel="noopener noreferrer"
          className="flex items-center gap-1 text-sky-400 hover:text-sky-300 hover:underline"
        >
          <span>Federal Complaint Portal</span>
          <ExternalLink className="w-3 h-3" />
        </a>
      </div>
    </div>
  );
}
