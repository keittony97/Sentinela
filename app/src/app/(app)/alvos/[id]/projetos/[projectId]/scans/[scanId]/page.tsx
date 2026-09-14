import { notFound } from "next/navigation";
import { TerminalPrompt } from "@/components/terminal/TerminalPrompt";
import { createClient } from "@/lib/supabase/server";
import { ScanLiveView } from "./ScanLiveView";

export default async function ScanDetailPage({
  params,
}: {
  params: Promise<{ id: string; projectId: string; scanId: string }>;
}) {
  const { id, projectId, scanId } = await params;
  const supabase = await createClient();

  const { data: scan } = await supabase.from("scans").select("*").eq("id", scanId).single();
  if (!scan) notFound();

  const { data: logs } = await supabase
    .from("scan_logs")
    .select("*")
    .eq("scan_id", scanId)
    .order("created_at", { ascending: true });

  const { data: findings } = await supabase
    .from("findings")
    .select("*")
    .eq("scan_id", scanId)
    .order("created_at", { ascending: true });

  return (
    <div className="flex flex-1 flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <TerminalPrompt path="~/scan" className="text-lg" />
        <a
          href={`/alvos/${id}/projetos/${projectId}/scans/${scanId}/relatorio`}
          className="border border-[var(--color-border-bright)] px-3 py-1.5 text-sm text-[var(--color-phosphor)] hover:bg-[var(--color-phosphor)] hover:text-black"
        >
          exportar relatório deste scan (PDF) »
        </a>
      </div>
      <ScanLiveView
        scanId={scanId}
        initialScan={scan}
        initialLogs={logs ?? []}
        initialFindings={findings ?? []}
      />
    </div>
  );
}
