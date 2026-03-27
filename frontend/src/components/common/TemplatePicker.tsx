import { useState } from 'react';
import { FileCode2 } from 'lucide-react';
import { CSPM_TEMPLATES, KAC_TEMPLATES } from '../../data/regoHelpContent';

interface TemplatePickerProps {
  variant: 'cspm' | 'kac';
  onSelect: (code: string) => void;
  currentCode?: string;
}

export default function TemplatePicker({ variant, onSelect, currentCode }: TemplatePickerProps) {
  const [selected, setSelected] = useState('');
  const [pendingCode, setPendingCode] = useState<string | null>(null);
  const templates = variant === 'cspm' ? CSPM_TEMPLATES : KAC_TEMPLATES;

  const handleChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const templateId = e.target.value;
    if (!templateId) return;

    const template = templates.find((t) => t.id === templateId);
    if (!template) return;

    setSelected(templateId);

    // If editor has meaningful content, ask for confirmation
    const hasContent = currentCode && currentCode.trim().length > 0;
    const isDefault = variant === 'kac' && currentCode?.includes('# Your deny logic here');
    if (hasContent && !isDefault) {
      setPendingCode(template.code);
    } else {
      onSelect(template.code);
      setSelected('');
    }
  };

  const confirmLoad = () => {
    if (pendingCode) {
      onSelect(pendingCode);
      setPendingCode(null);
      setSelected('');
    }
  };

  const cancelLoad = () => {
    setPendingCode(null);
    setSelected('');
  };

  return (
    <div>
      <div className="flex items-center gap-2">
        <FileCode2 size={16} className="text-gray-400 shrink-0" />
        <select
          value={selected}
          onChange={handleChange}
          className="flex-1 rounded-lg border border-[#2e2b3a] bg-[#171520] px-3 py-2 text-sm text-gray-300 outline-none focus:border-[#ED1C24]/60"
        >
          <option value="">Load an example template...</option>
          {templates.map((t) => (
            <option key={t.id} value={t.id}>
              {t.name} — {t.description}
            </option>
          ))}
        </select>
      </div>

      {pendingCode && (
        <div className="mt-2 flex items-center gap-3 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2">
          <span className="text-xs text-amber-300">This will replace your current code.</span>
          <button
            type="button"
            onClick={confirmLoad}
            className="rounded bg-[#ED1C24] px-2.5 py-1 text-xs font-medium text-white hover:bg-[#c4161d] transition-colors"
          >
            Load
          </button>
          <button
            type="button"
            onClick={cancelLoad}
            className="rounded border border-[#3a3650] px-2.5 py-1 text-xs text-gray-400 hover:text-gray-200 transition-colors"
          >
            Cancel
          </button>
        </div>
      )}
    </div>
  );
}
