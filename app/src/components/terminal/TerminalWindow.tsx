import type { ReactNode } from "react";

type TerminalWindowProps = {
  title: string;
  children: ReactNode;
  className?: string;
  accent?: "phosphor" | "amber" | "cyan";
};

const accentColor: Record<NonNullable<TerminalWindowProps["accent"]>, string> = {
  phosphor: "var(--color-phosphor)",
  amber: "var(--color-amber)",
  cyan: "var(--color-cyan)",
};

export function TerminalWindow({
  title,
  children,
  className = "",
  accent = "phosphor",
}: TerminalWindowProps) {
  return (
    <div className={`term-window flex flex-col ${className}`}>
      <div className="term-window-titlebar flex items-center gap-2 px-3 py-2">
        <span className="flex gap-1.5" aria-hidden="true">
          <span className="h-2.5 w-2.5 rounded-full bg-[var(--color-critical)]/70" />
          <span className="h-2.5 w-2.5 rounded-full bg-[var(--color-amber)]/70" />
          <span className="h-2.5 w-2.5 rounded-full bg-[var(--color-phosphor)]/70" />
        </span>
        <span
          className="text-xs tracking-tight"
          style={{ color: accentColor[accent] }}
        >
          {title}
        </span>
      </div>
      <div className="flex-1 p-4">{children}</div>
    </div>
  );
}
