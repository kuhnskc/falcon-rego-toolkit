import { useState, useCallback } from 'react';
import { ChevronRight, ChevronDown, Copy, Check } from 'lucide-react';

interface JsonViewerProps {
  data: unknown;
  title?: string;
}

export default function JsonViewer({ data, title }: JsonViewerProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(JSON.stringify(data, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, [data]);

  return (
    <div className="rounded-lg border border-[#2e2b3a] bg-[#171520] overflow-hidden">
      {(title || true) && (
        <div className="flex items-center justify-between border-b border-[#2e2b3a] px-4 py-2">
          {title && (
            <span className="text-sm font-medium text-gray-300">{title}</span>
          )}
          <button
            onClick={handleCopy}
            className="ml-auto flex items-center gap-1.5 rounded px-2 py-1 text-xs text-gray-400 hover:bg-[#2e2b3a] hover:text-gray-200 transition-colors"
          >
            {copied ? (
              <>
                <Check size={12} /> Copied
              </>
            ) : (
              <>
                <Copy size={12} /> Copy
              </>
            )}
          </button>
        </div>
      )}
      <div className="overflow-auto p-4">
        <JsonNode value={data} depth={0} />
      </div>
    </div>
  );
}

interface JsonNodeProps {
  value: unknown;
  depth: number;
  keyName?: string;
}

function JsonNode({ value, depth, keyName }: JsonNodeProps) {
  const [collapsed, setCollapsed] = useState(depth > 2);

  if (value === null) {
    return (
      <div style={{ paddingLeft: depth * 16 }}>
        {keyName !== undefined && (
          <span className="text-purple-400">"{keyName}"</span>
        )}
        {keyName !== undefined && <span className="text-gray-400">: </span>}
        <span className="text-gray-500 italic">null</span>
      </div>
    );
  }

  if (typeof value === 'boolean') {
    return (
      <div style={{ paddingLeft: depth * 16 }}>
        {keyName !== undefined && (
          <span className="text-purple-400">"{keyName}"</span>
        )}
        {keyName !== undefined && <span className="text-gray-400">: </span>}
        <span className="text-orange-400">{String(value)}</span>
      </div>
    );
  }

  if (typeof value === 'number') {
    return (
      <div style={{ paddingLeft: depth * 16 }}>
        {keyName !== undefined && (
          <span className="text-purple-400">"{keyName}"</span>
        )}
        {keyName !== undefined && <span className="text-gray-400">: </span>}
        <span className="text-cyan-400">{value}</span>
      </div>
    );
  }

  if (typeof value === 'string') {
    return (
      <div style={{ paddingLeft: depth * 16 }}>
        {keyName !== undefined && (
          <span className="text-purple-400">"{keyName}"</span>
        )}
        {keyName !== undefined && <span className="text-gray-400">: </span>}
        <span className="text-green-400">"{value}"</span>
      </div>
    );
  }

  if (Array.isArray(value)) {
    if (value.length === 0) {
      return (
        <div style={{ paddingLeft: depth * 16 }}>
          {keyName !== undefined && (
            <span className="text-purple-400">"{keyName}"</span>
          )}
          {keyName !== undefined && <span className="text-gray-400">: </span>}
          <span className="text-gray-400">[]</span>
        </div>
      );
    }

    return (
      <div style={{ paddingLeft: depth * 16 }}>
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="inline-flex items-center gap-0.5 text-gray-400 hover:text-gray-200 transition-colors"
        >
          {collapsed ? <ChevronRight size={14} /> : <ChevronDown size={14} />}
          {keyName !== undefined && (
            <span className="text-purple-400">"{keyName}"</span>
          )}
          {keyName !== undefined && <span className="text-gray-400">: </span>}
          <span className="text-gray-500">
            [{collapsed ? `${value.length} items` : ''}
          </span>
        </button>
        {!collapsed && (
          <>
            {value.map((item, idx) => (
              <JsonNode key={idx} value={item} depth={depth + 1} />
            ))}
            <div style={{ paddingLeft: depth * 16 }}>
              <span className="text-gray-500">]</span>
            </div>
          </>
        )}
        {collapsed && <span className="text-gray-500">]</span>}
      </div>
    );
  }

  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>);

    if (entries.length === 0) {
      return (
        <div style={{ paddingLeft: depth * 16 }}>
          {keyName !== undefined && (
            <span className="text-purple-400">"{keyName}"</span>
          )}
          {keyName !== undefined && <span className="text-gray-400">: </span>}
          <span className="text-gray-400">{'{}'}</span>
        </div>
      );
    }

    return (
      <div style={{ paddingLeft: depth * 16 }}>
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="inline-flex items-center gap-0.5 text-gray-400 hover:text-gray-200 transition-colors"
        >
          {collapsed ? <ChevronRight size={14} /> : <ChevronDown size={14} />}
          {keyName !== undefined && (
            <span className="text-purple-400">"{keyName}"</span>
          )}
          {keyName !== undefined && <span className="text-gray-400">: </span>}
          <span className="text-gray-500">
            {'{'}{collapsed ? `${entries.length} keys` : ''}
          </span>
        </button>
        {!collapsed && (
          <>
            {entries.map(([k, v]) => (
              <JsonNode key={k} value={v} depth={depth + 1} keyName={k} />
            ))}
            <div style={{ paddingLeft: depth * 16 }}>
              <span className="text-gray-500">{'}'}</span>
            </div>
          </>
        )}
        {collapsed && <span className="text-gray-500">{'}'}</span>}
      </div>
    );
  }

  return (
    <div style={{ paddingLeft: depth * 16 }}>
      <span className="text-gray-400">{String(value)}</span>
    </div>
  );
}
