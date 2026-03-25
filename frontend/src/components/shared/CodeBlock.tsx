import { useState } from "react";
import { Check, Copy } from "lucide-react";
import { cn } from "@/lib/utils";

interface CodeBlockProps {
  code: string;
  language?: string;
  className?: string;
}

export function CodeBlock({ code, language, className }: CodeBlockProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className={cn("relative group rounded-lg border border-zinc-800 bg-zinc-950", className)}>
      {language && (
        <div className="flex items-center justify-between px-3 py-1.5 border-b border-zinc-800">
          <span className="text-[10px] uppercase tracking-wider text-zinc-500 font-medium">
            {language}
          </span>
          <button
            onClick={handleCopy}
            className="text-zinc-500 hover:text-zinc-300 transition-colors"
            aria-label="Copy code"
          >
            {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
          </button>
        </div>
      )}
      {!language && (
        <button
          onClick={handleCopy}
          className="absolute top-2 right-2 text-zinc-500 hover:text-zinc-300 transition-colors opacity-0 group-hover:opacity-100"
          aria-label="Copy code"
        >
          {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
        </button>
      )}
      <pre className="p-3 overflow-x-auto">
        <code className="text-sm font-mono text-zinc-300 leading-relaxed">{code}</code>
      </pre>
    </div>
  );
}
