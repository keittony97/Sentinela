type TerminalPromptProps = {
  user?: string;
  host?: string;
  path?: string;
  className?: string;
};

export function TerminalPrompt({
  user = "sentinela",
  host = "org",
  path = "~",
  className = "",
}: TerminalPromptProps) {
  return (
    <span className={`whitespace-pre ${className}`}>
      <span className="text-[var(--color-phosphor)]">{user}</span>
      <span className="text-[var(--color-fg-muted)]">@</span>
      <span className="text-[var(--color-cyan)]">{host}</span>
      <span className="text-[var(--color-fg-muted)]">:</span>
      <span className="text-[var(--color-amber)]">{path}</span>
      <span className="text-[var(--color-fg-muted)]">$</span>
    </span>
  );
}
