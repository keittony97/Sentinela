import type { Database } from "@/lib/supabase/database.types";

type ScanStatus = Database["public"]["Enums"]["scan_status"];

const config: Record<ScanStatus, { label: string; color: string }> = {
  na_fila: { label: "NA FILA", color: "var(--color-fg-dim)" },
  em_execucao: { label: "EM EXECUÇÃO", color: "var(--color-cyan)" },
  concluido: { label: "CONCLUÍDO", color: "var(--color-phosphor)" },
  falhou: { label: "FALHOU", color: "var(--color-critical)" },
  cancelado: { label: "CANCELADO", color: "var(--color-fg-muted)" },
};

export function ScanStatusBadge({ status }: { status: ScanStatus }) {
  const { label, color } = config[status];
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-sm border px-1.5 py-0.5 text-xs font-bold tracking-wide"
      style={{ borderColor: color, color }}
    >
      {status === "em_execucao" && (
        <span
          className="h-1.5 w-1.5 rounded-full"
          style={{ backgroundColor: color, animation: "blink-cursor 1s steps(1) infinite" }}
        />
      )}
      {label}
    </span>
  );
}
