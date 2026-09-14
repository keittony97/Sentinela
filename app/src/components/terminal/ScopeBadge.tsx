import type { Database } from "@/lib/supabase/database.types";

type Scope = Database["public"]["Enums"]["target_scope"];

const config: Record<Scope, { label: string; color: string }> = {
  intranet: { label: "INTRANET", color: "var(--color-amber)" },
  internet: { label: "INTERNET", color: "var(--color-cyan)" },
};

export function ScopeBadge({ scope }: { scope: Scope }) {
  const { label, color } = config[scope];
  return (
    <span
      className="inline-flex items-center rounded-sm border px-1.5 py-0.5 text-xs font-bold tracking-wide"
      style={{ borderColor: color, color }}
    >
      {label}
    </span>
  );
}
