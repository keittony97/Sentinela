"use client";

import { useEffect, useRef, useState } from "react";
import { createClient } from "@/lib/supabase/client";
import { ScanStatusBadge } from "@/components/terminal/ScanStatusBadge";
import { SeverityBadge, type Severity } from "@/components/terminal/SeverityBadge";
import type { Tables } from "@/lib/supabase/database.types";

type Scan = Tables<"scans">;
type ScanLog = Tables<"scan_logs">;
type Finding = Tables<"findings">;

const severityRank: Record<Severity, number> = {
  critico: 0,
  alto: 1,
  medio: 2,
  baixo: 3,
  informativo: 4,
};

const levelColor: Record<string, string> = {
  info: "var(--color-fg-dim)",
  warning: "var(--color-amber)",
  error: "var(--color-critical)",
};

export function ScanLiveView({
  scanId,
  initialScan,
  initialLogs,
  initialFindings,
}: {
  scanId: string;
  initialScan: Scan;
  initialLogs: ScanLog[];
  initialFindings: Finding[];
}) {
  const [scan, setScan] = useState(initialScan);
  const [logs, setLogs] = useState(initialLogs);
  const [findings, setFindings] = useState(initialFindings);
  const logEndRef = useRef<HTMLDivElement>(null);
  const statusRef = useRef(initialScan.status);

  useEffect(() => {
    statusRef.current = scan.status;
  }, [scan.status]);

  useEffect(() => {
    const supabase = createClient();
    let cancelled = false;
    let pollId: ReturnType<typeof setInterval> | undefined;

    // O worker pode terminar um scan (poll a cada ~2s) mais rápido do que o
    // navegador estabelece o WebSocket da Realtime — eventos que acontecem
    // antes da inscrição ficar ativa não são entregues retroativamente.
    // Por isso, além de escutar ao vivo, buscamos o estado atual assim que
    // a inscrição conecta e continuamos buscando a cada 2s como rede de
    // segurança enquanto o scan não terminar.
    async function reconcile() {
      const [{ data: freshScan }, { data: freshLogs }, { data: freshFindings }] = await Promise.all([
        supabase.from("scans").select("*").eq("id", scanId).single(),
        supabase.from("scan_logs").select("*").eq("scan_id", scanId).order("created_at", { ascending: true }),
        supabase
          .from("findings")
          .select("*")
          .eq("scan_id", scanId)
          .order("created_at", { ascending: true }),
      ]);
      if (cancelled) return;
      if (freshScan) setScan(freshScan);
      if (freshLogs) setLogs(freshLogs);
      if (freshFindings) setFindings(freshFindings);
    }

    function startPolling() {
      pollId = setInterval(() => {
        if (
          statusRef.current === "concluido" ||
          statusRef.current === "falhou" ||
          statusRef.current === "cancelado"
        ) {
          clearInterval(pollId);
          return;
        }
        reconcile();
      }, 2000);
    }

    const channel = supabase
      .channel(`scan-${scanId}`)
      .on(
        "postgres_changes",
        { event: "INSERT", schema: "public", table: "scan_logs", filter: `scan_id=eq.${scanId}` },
        (payload) => {
          const row = payload.new as ScanLog;
          setLogs((prev) => (prev.some((l) => l.id === row.id) ? prev : [...prev, row]));
        },
      )
      .on(
        "postgres_changes",
        { event: "UPDATE", schema: "public", table: "scans", filter: `id=eq.${scanId}` },
        (payload) => setScan(payload.new as Scan),
      )
      .on(
        "postgres_changes",
        { event: "INSERT", schema: "public", table: "findings", filter: `scan_id=eq.${scanId}` },
        (payload) => {
          const row = payload.new as Finding;
          setFindings((prev) => (prev.some((f) => f.id === row.id) ? prev : [...prev, row]));
        },
      )
      .subscribe((status) => {
        if (status === "SUBSCRIBED") {
          reconcile();
          startPolling();
        }
      });

    return () => {
      cancelled = true;
      clearInterval(pollId);
      supabase.removeChannel(channel);
    };
  }, [scanId]);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  const sortedFindings = [...findings].sort(
    (a, b) => severityRank[a.severity] - severityRank[b.severity],
  );

  const isRunning = scan.status === "na_fila" || scan.status === "em_execucao";

  return (
    <div className="flex flex-1 flex-col gap-4">
      <div className="flex items-center gap-3">
        <ScanStatusBadge status={scan.status} />
        {isRunning && (
          <span className="text-xs text-[var(--color-fg-muted)]">
            aguardando o worker processar...
          </span>
        )}
      </div>

      <div className="term-window flex flex-col">
        <div className="term-window-titlebar flex items-center gap-2 px-3 py-2">
          <span className="text-xs text-[var(--color-cyan)]">user@sentinela:~/scan-log$</span>
        </div>
        <div className="flex max-h-96 flex-col gap-0.5 overflow-y-auto p-4 font-mono text-xs">
          {logs.length === 0 && (
            <span className="text-[var(--color-fg-muted)]">
              nenhuma linha de log ainda...
            </span>
          )}
          {logs.map((line) => (
            <p key={line.id} style={{ color: levelColor[line.level] ?? "var(--color-fg)" }}>
              <span className="text-[var(--color-fg-muted)]">
                [{new Date(line.created_at).toLocaleTimeString("pt-BR")}]
              </span>{" "}
              <span className="text-[var(--color-fg-muted)]">[{line.tool}]</span>{" "}
              {line.message}
            </p>
          ))}
          {isRunning && <span className="term-cursor text-[var(--color-phosphor)]" />}
          <div ref={logEndRef} />
        </div>
      </div>

      {scan.status === "concluido" && (
        <div className="term-window flex flex-col">
          <div className="term-window-titlebar flex items-center gap-2 px-3 py-2">
            <span className="text-xs text-[var(--color-phosphor)]">
              user@sentinela:~/achados$
            </span>
          </div>
          <div className="p-4">
            {sortedFindings.length === 0 ? (
              <p className="text-sm text-[var(--color-fg-dim)]">
                Nenhum achado — a verificação não encontrou problemas.
              </p>
            ) : (
              <ul className="flex flex-col gap-2">
                {sortedFindings.map((finding) => (
                  <li
                    key={finding.id}
                    className="border-b border-[var(--color-border)] pb-2 last:border-none"
                  >
                    <details>
                      <summary className="flex cursor-pointer list-none flex-wrap items-center justify-between gap-2 py-1 text-sm">
                        <span>{finding.title}</span>
                        <SeverityBadge severity={finding.severity} />
                      </summary>
                      <div className="mt-2 flex flex-col gap-2 pl-2 text-xs text-[var(--color-fg-dim)]">
                        {finding.description && (
                          <p>
                            <span className="text-[var(--color-fg-muted)]">como foi encontrada: </span>
                            {finding.description}
                          </p>
                        )}
                        {finding.impact && (
                          <p>
                            <span className="text-[var(--color-fg-muted)]">impacto: </span>
                            {finding.impact}
                          </p>
                        )}
                        {finding.recommendation && (
                          <p>
                            <span className="text-[var(--color-fg-muted)]">como corrigir: </span>
                            {finding.recommendation}
                          </p>
                        )}
                        {(finding.cwe || finding.owasp_category) && (
                          <p>
                            <span className="text-[var(--color-fg-muted)]">referências: </span>
                            {[finding.cwe, finding.owasp_category].filter(Boolean).join(" · ")}
                          </p>
                        )}
                      </div>
                    </details>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
