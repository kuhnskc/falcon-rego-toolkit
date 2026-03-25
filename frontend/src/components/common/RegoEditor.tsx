import { useRef, useCallback } from 'react';
import Editor, { type OnMount, type Monaco } from '@monaco-editor/react';
import type { editor } from 'monaco-editor';

interface RegoEditorProps {
  value: string;
  onChange: (value: string) => void;
  height?: string;
  readOnly?: boolean;
}

const REGO_LANGUAGE_ID = 'rego';

const REGO_KEYWORDS = [
  'package',
  'import',
  'default',
  'if',
  'not',
  'in',
  'contains',
  'every',
  'some',
  'with',
  'else',
  'true',
  'false',
  'null',
  'input',
  'data',
  'as',
  'result',
];

function registerRegoLanguage(monaco: Monaco) {
  if (monaco.languages.getLanguages().some((lang: { id: string }) => lang.id === REGO_LANGUAGE_ID)) {
    return;
  }

  monaco.languages.register({ id: REGO_LANGUAGE_ID });

  monaco.languages.setMonarchTokensProvider(REGO_LANGUAGE_ID, {
    keywords: REGO_KEYWORDS,
    operators: [':=', '==', '!=', '<', '>', '<=', '>=', '+', '-', '*', '/', '%', '&', '|'],
    symbols: /[=><!~?:&|+\-*/^%]+/,

    tokenizer: {
      root: [
        // Comments
        [/#.*$/, 'comment'],

        // Strings
        [/"([^"\\]|\\.)*$/, 'string.invalid'],
        [/"/, { token: 'string.quote', bracket: '@open', next: '@string' }],
        [/`[^`]*`/, 'string'],

        // Numbers
        [/\d*\.\d+([eE][-+]?\d+)?/, 'number.float'],
        [/0[xX][0-9a-fA-F]+/, 'number.hex'],
        [/\d+/, 'number'],

        // Identifiers and keywords
        [
          /[a-zA-Z_]\w*/,
          {
            cases: {
              '@keywords': 'keyword',
              '@default': 'identifier',
            },
          },
        ],

        // Operators
        [
          /@symbols/,
          {
            cases: {
              '@operators': 'operator',
              '@default': '',
            },
          },
        ],

        // Brackets
        [/[{}()[\]]/, '@brackets'],

        // Delimiters
        [/[;,.]/, 'delimiter'],
      ],

      string: [
        [/[^\\"]+/, 'string'],
        [/\\./, 'string.escape'],
        [/"/, { token: 'string.quote', bracket: '@close', next: '@pop' }],
      ],
    },
  });

  monaco.editor.defineTheme('rego-dark', {
    base: 'vs-dark',
    inherit: true,
    rules: [
      { token: 'keyword', foreground: 'c586c0', fontStyle: 'bold' },
      { token: 'comment', foreground: '6a9955', fontStyle: 'italic' },
      { token: 'string', foreground: 'ce9178' },
      { token: 'string.escape', foreground: 'd7ba7d' },
      { token: 'number', foreground: 'b5cea8' },
      { token: 'number.float', foreground: 'b5cea8' },
      { token: 'number.hex', foreground: 'b5cea8' },
      { token: 'operator', foreground: 'd4d4d4' },
      { token: 'identifier', foreground: '9cdcfe' },
      { token: 'delimiter', foreground: 'd4d4d4' },
    ],
    colors: {
      'editor.background': '#171520',
      'editor.foreground': '#d4d4d4',
      'editorLineNumber.foreground': '#4a4d5a',
      'editorLineNumber.activeForeground': '#8a8d9a',
      'editor.selectionBackground': '#2e2b3a',
      'editor.lineHighlightBackground': '#23202e',
      'editorCursor.foreground': '#ED1C24',
      'editorWidget.background': '#23202e',
      'editorWidget.border': '#2e2b3a',
      'input.background': '#23202e',
      'input.border': '#2e2b3a',
      'dropdown.background': '#23202e',
      'dropdown.border': '#2e2b3a',
    },
  });
}

export default function RegoEditor({
  value,
  onChange,
  height = '400px',
  readOnly = false,
}: RegoEditorProps) {
  const editorRef = useRef<editor.IStandaloneCodeEditor | null>(null);

  const handleBeforeMount = useCallback((monaco: Monaco) => {
    registerRegoLanguage(monaco);
  }, []);

  const handleMount: OnMount = useCallback((editor) => {
    editorRef.current = editor;
  }, []);

  const handleChange = useCallback(
    (val: string | undefined) => {
      onChange(val ?? '');
    },
    [onChange],
  );

  return (
    <div className="overflow-hidden rounded-lg border border-[#2e2b3a]">
      <Editor
        height={height}
        language={REGO_LANGUAGE_ID}
        theme="rego-dark"
        value={value}
        onChange={handleChange}
        beforeMount={handleBeforeMount}
        onMount={handleMount}
        options={{
          readOnly,
          minimap: { enabled: false },
          fontSize: 14,
          lineHeight: 22,
          padding: { top: 12, bottom: 12 },
          scrollBeyondLastLine: false,
          automaticLayout: true,
          wordWrap: 'on',
          tabSize: 2,
          renderLineHighlight: 'line',
          cursorBlinking: 'smooth',
          smoothScrolling: true,
          contextmenu: true,
          folding: true,
          lineNumbers: 'on',
          glyphMargin: false,
          bracketPairColorization: { enabled: true },
        }}
      />
    </div>
  );
}
