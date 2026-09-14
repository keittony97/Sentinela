export type Severity = "critico" | "alto" | "medio" | "baixo" | "informativo";

const severityConfig: Record<Severity, { label: string; color: string }> = {
  critico: { label: "CRÍTICO", color: "var(--color-critical)" },
  alto: { label: "ALTO", color: "var(--color-high)" },
  medio: { label: "MÉDIO", color: "var(--color-medium)" },
  baixo: { label: "BAIXO", color: "var(--color-low)" },
  informativo: { label: "INFO", color: "var(--color-info)" },
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  const { label, color } = severityConfig[severity];
  return (
    <span
      className="inline-flex items-center rounded-sm px-2 py-0.5 text-xs font-bold tracking-wide text-black"
      style={{ backgroundColor: color }}
    >
      {label}
    </span>
  );
}
