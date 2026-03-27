import { useState } from 'react';
import { BookOpen, ChevronDown, ChevronRight, CheckCircle2, Code2, AlertTriangle } from 'lucide-react';
import { CSPM_HELP, KAC_HELP } from '../../data/regoHelpContent';

interface RegoHelpPanelProps {
  variant: 'cspm' | 'kac';
}

export default function RegoHelpPanel({ variant }: RegoHelpPanelProps) {
  const [isOpen, setIsOpen] = useState(false);
  const help = variant === 'cspm' ? CSPM_HELP : KAC_HELP;

  return (
    <div className="rounded-xl border border-[#2e2b3a] bg-[#1c1928]">
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className="flex w-full items-center gap-2 px-4 py-3 text-left text-sm font-medium text-gray-300 hover:text-gray-100 transition-colors"
      >
        <BookOpen size={16} className="text-[#ED1C24] shrink-0" />
        <span className="flex-1">Rego Writing Guide</span>
        {isOpen ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
      </button>

      {isOpen && (
        <div className="border-t border-[#2e2b3a] px-4 pb-4 pt-3 space-y-4">
          {/* Rules */}
          <div>
            <h4 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-gray-400 mb-2">
              <CheckCircle2 size={13} className="text-green-400" />
              Rules
            </h4>
            <ul className="space-y-1.5">
              {help.rules.map((rule) => (
                <li key={rule.title} className="text-xs text-gray-400">
                  <span className="font-medium text-gray-300">{rule.title}:</span>{' '}
                  <InlineCode text={rule.text} />
                </li>
              ))}
            </ul>
          </div>

          {/* Patterns */}
          <div>
            <h4 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-gray-400 mb-2">
              <Code2 size={13} className="text-blue-400" />
              Common Patterns
            </h4>
            <ul className="space-y-1.5">
              {help.patterns.map((pattern, i) => (
                <li key={i} className="text-xs text-gray-400">
                  <InlineCode text={pattern} />
                </li>
              ))}
            </ul>
          </div>

          {/* Pitfalls */}
          <div>
            <h4 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-gray-400 mb-2">
              <AlertTriangle size={13} className="text-amber-400" />
              Pitfalls to Avoid
            </h4>
            <ul className="space-y-1.5">
              {help.pitfalls.map((pitfall, i) => (
                <li key={i} className="text-xs text-gray-400">
                  <InlineCode text={pitfall} />
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}

/** Renders text with backtick-wrapped segments as <code> elements */
function InlineCode({ text }: { text: string }) {
  const parts = text.split(/(`[^`]+`)/g);
  return (
    <>
      {parts.map((part, i) =>
        part.startsWith('`') && part.endsWith('`') ? (
          <code key={i} className="rounded bg-[#2e2b3a] px-1 py-0.5 text-[11px] text-gray-300 font-mono">
            {part.slice(1, -1)}
          </code>
        ) : (
          <span key={i}>{part}</span>
        )
      )}
    </>
  );
}
