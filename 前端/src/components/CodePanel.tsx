import { useRef, type ReactNode, type UIEvent } from 'react';

function inlineMarkdown(line: string): ReactNode {
  const tokens = line.split(/(`[^`]*`|\*\*[^*]+\*\*|\[[^\]]+\]\([^)]+\))/g);
  return tokens.map((token, index) => {
    if (token.startsWith('`')) return <span key={index} className="text-amber">{token}</span>;
    if (token.startsWith('**')) return <span key={index} className="font-semibold text-slate-100">{token}</span>;
    if (token.startsWith('[')) return <span key={index} className="text-cyan">{token}</span>;
    return token;
  });
}

function MarkdownLine({ line }: { line: string }) {
  if (/^#{1,6}\s/.test(line)) {
    const [, hashes, text] = line.match(/^(#{1,6})(\s.*)$/) ?? [];
    return <><span className="text-cyan">{hashes}</span><span className="font-semibold text-slate-100">{text}</span></>;
  }
  if (/^\s*```/.test(line)) return <span className="text-amber">{line}</span>;
  if (line.includes('|')) {
    return line.split(/(\|)/g).map((part, index) =>
      part === '|' ? <span key={index} className="text-slate-600">{part}</span> : <span key={index} className={/^\s*[-:]+\s*$/.test(part) ? 'text-slate-600' : 'text-emerald/90'}>{part}</span>,
    );
  }
  if (/^\s*[-*+]\s/.test(line)) return <span className="text-slate-300">{inlineMarkdown(line)}</span>;
  return <span className="text-slate-400">{inlineMarkdown(line)}</span>;
}

export function CodeView({ code, ariaLabel, empty = 'No output available', compact = false }: {
  code: string;
  ariaLabel: string;
  empty?: string;
  compact?: boolean;
}) {
  const lines = code ? code.split('\n') : [];
  if (!lines.length) {
    return <div className="grid h-full min-h-24 place-items-center p-4 font-mono text-[9px] text-slate-600">{empty}</div>;
  }
  return (
    <div role="region" aria-label={ariaLabel} tabIndex={0} className="code-scroll h-full overflow-auto bg-[#0a1018]/60">
      <pre className={compact ? 'min-w-max p-2 font-mono text-[9px] leading-[17px]' : 'min-w-max p-2.5 font-mono text-[10px] leading-[20px]'}>
        {lines.map((line, index) => (
          <div key={`line-${index}`} className="flex min-h-[20px] hover:bg-white/[0.025]">
            <span aria-hidden="true" className="sticky left-0 z-10 mr-3 inline-block w-6 flex-none select-none border-r border-border/60 bg-[#0a1018] pr-2 text-right text-slate-700">{index + 1}</span>
            <code className="whitespace-pre pr-5"><MarkdownLine line={line} /></code>
          </div>
        ))}
      </pre>
    </div>
  );
}

export function HtmlEditor({ value, onChange, ariaLabel = 'Raw untrusted HTML payload', rows }: {
  value: string;
  onChange: (value: string) => void;
  ariaLabel?: string;
  rows?: number;
}) {
  const gutterRef = useRef<HTMLDivElement>(null);
  const lines = value.split('\n');
  const syncScroll = (event: UIEvent<HTMLTextAreaElement>) => {
    if (gutterRef.current) gutterRef.current.scrollTop = event.currentTarget.scrollTop;
  };
  return (
    <div className="relative flex h-full min-h-0 overflow-hidden bg-[#0a1018]/60">
      <div ref={gutterRef} aria-hidden="true" className="code-scroll w-10 flex-none overflow-hidden border-r border-border/60 bg-[#0b111a] py-2.5 text-right font-mono text-[10px] leading-[20px] text-slate-700">
        {lines.map((_, index) => <div key={`gutter-${index}`} className="pr-2">{index + 1}</div>)}
      </div>
      <textarea
        aria-label={ariaLabel}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        onScroll={syncScroll}
        rows={rows}
        wrap="off"
        spellCheck={false}
        autoCapitalize="off"
        autoCorrect="off"
        className="code-scroll h-full min-h-0 flex-1 resize-none overflow-auto bg-transparent p-2.5 font-mono text-[10px] leading-[20px] text-slate-300 caret-cyan outline-none placeholder:text-slate-700"
        placeholder="<html>…</html>"
      />
    </div>
  );
}
