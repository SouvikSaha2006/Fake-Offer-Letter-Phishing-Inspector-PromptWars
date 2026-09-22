import React from 'react';
import { AlertOctagon, AlertTriangle, Info, CheckCircle2, ShieldCheck } from 'lucide-react';

export default function FlagBadges({ findings = [], domainDetails = [] }) {
  // Sort findings by severity: CRITICAL first, then HIGH, MEDIUM, INFO
  const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  const sortedFindings = [...findings].sort((a, b) => {
    const orderA = severityOrder[a.severity] ?? 5;
    const orderB = severityOrder[b.severity] ?? 5;
    return orderA - orderB;
  });

  const getSeverityStyles = (severity) => {
    switch (severity) {
      case 'CRITICAL':
        return {
          pill: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
          border: 'border-rose-500/20 bg-rose-950/10 hover:border-rose-500/40',
          points: '+35-65 PTS',
          icon: AlertOctagon,
          codeColor: 'text-rose-300 bg-rose-950/40 border-rose-800/40'
        };
      case 'HIGH':
        return {
          pill: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
          border: 'border-amber-500/20 bg-amber-950/10 hover:border-amber-500/40',
          points: '+25-45 PTS',
          icon: AlertTriangle,
          codeColor: 'text-amber-300 bg-amber-950/40 border-amber-800/40'
        };
      case 'MEDIUM':
        return {
          pill: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
          border: 'border-yellow-500/20 bg-yellow-950/10 hover:border-yellow-500/40',
          points: '+15 PTS',
          icon: AlertTriangle,
          codeColor: 'text-yellow-300 bg-yellow-950/40 border-yellow-800/40'
        };
      case 'INFO':
      default:
        return {
          pill: 'bg-sky-500/10 text-sky-400 border-sky-500/30',
          border: 'border-sky-500/20 bg-sky-950/10 hover:border-sky-500/40',
          points: '+5 PTS',
          icon: Info,
          codeColor: 'text-sky-300 bg-sky-950/40 border-sky-800/40'
        };
    }
  };

  return (
    <div 
      data-testid="forensic-findings-list"
      className="bg-[#0f172a] rounded-xl border border-slate-800/90 p-5 shadow-xl space-y-4"
    >
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
          Forensic Findings Matrix ({findings.length})
        </h3>
        <span className="text-[11px] font-mono text-slate-400">
          FILTER: SEVERITY DESC
        </span>
      </div>

      {/* Domain Registry Telemetry Badges */}
      {domainDetails.length > 0 && (
        <div className="p-3 bg-[#1e293b]/40 rounded-lg border border-slate-800 space-y-2">
          <div className="text-[11px] font-mono uppercase text-slate-400">
            Identified Domain Telemetry
          </div>
          <div className="flex flex-wrap gap-2">
            {domainDetails.map((dom, idx) => (
              <div 
                key={idx}
                className="flex items-center gap-2 px-2.5 py-1 rounded bg-slate-900 border border-slate-700/60 font-mono text-xs"
              >
                <span className="text-slate-200 font-medium">{dom.domain}</span>
                {dom.isFreeProvider ? (
                  <span className="px-1.5 py-0.2 rounded text-[10px] bg-amber-500/15 text-amber-300 border border-amber-500/30">
                    Free Mail Provider
                  </span>
                ) : dom.ageInDays !== null ? (
                  <span className={`px-1.5 py-0.2 rounded text-[10px] border ${
                    dom.ageInDays < 30 
                      ? 'bg-rose-500/15 text-rose-300 border-rose-500/30 font-bold' 
                      : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                  }`}>
                    Age: {dom.ageInDays} Days
                  </span>
                ) : (
                  <span className="px-1.5 py-0.2 rounded text-[10px] bg-slate-800 text-slate-400">
                    Registry: {dom.status}
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Findings List */}
      {sortedFindings.length === 0 ? (
        <div className="py-8 flex flex-col items-center justify-center text-center p-4 rounded-lg bg-emerald-950/10 border border-emerald-500/20">
          <ShieldCheck className="w-8 h-8 text-emerald-400 mb-2" />
          <h4 className="text-sm font-semibold text-emerald-300">
            Zero Threat Signatures Triggered
          </h4>
          <p className="text-xs text-slate-400 max-w-sm mt-1">
            The submitted payload contains no detectable advance fee schemes, fake cashier check instructions, or anomalous recruitment patterns.
          </p>
        </div>
      ) : (
        <div className="space-y-2.5">
          {sortedFindings.map((finding, idx) => {
            const styles = getSeverityStyles(finding.severity);
            const FindingIcon = styles.icon;

            return (
              <article 
                key={idx}
                className={`p-3.5 rounded-lg border transition-all ${styles.border}`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-start gap-2.5">
                    <FindingIcon className="w-4 h-4 shrink-0 mt-0.5" />
                    <div>
                      <h4 className="text-xs font-semibold text-slate-200 leading-snug">
                        {finding.title}
                      </h4>
                      <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                        {finding.detail}
                      </p>
                    </div>
                  </div>

                  <div className="flex flex-col items-end gap-1 shrink-0">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold tracking-tight border uppercase ${styles.pill}`}>
                      {finding.severity}
                    </span>
                    <span className="text-[10px] font-mono text-slate-400 tabular-nums">
                      {styles.points}
                    </span>
                  </div>
                </div>

                {finding.type && (
                  <div className="mt-2 pt-2 border-t border-slate-800/60 flex items-center gap-2">
                    <span className="text-[10px] font-mono text-slate-400">VECTOR:</span>
                    <code className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${styles.codeColor}`}>
                      {finding.type}
                    </code>
                    {finding.source && (
                      <span className="text-[10px] font-mono text-slate-400 ml-auto">
                        SRC: {finding.source}
                      </span>
                    )}
                  </div>
                )}
              </article>
            );
          })}
        </div>
      )}
    </div>
  );
}
