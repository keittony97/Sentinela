import type { Database } from "@/lib/supabase/database.types";

type LegalMode = Database["public"]["Enums"]["legal_mode"];

const config: Record<LegalMode, { label: string; color: string }> = {
  verificacao_externa: { label: "VERIFICAÇÃO EXTERNA (LEGAL)", color: "var(--color-phosphor)" },
  ambiente_teste: { label: "AMBIENTE DE TESTE", color: "var(--color-critical)" },
};

export function LegalModeBadge({ mode }: { mode: LegalMode }) {
  const { label, color } = config[mode];
  return (
    <span
      className="inline-flex items-center rounded-sm border px-1.5 py-0.5 text-xs font-bold tracking-wide"
      style={{ borderColor: color, color }}
    >
      {label}
    </span>
  );
}
