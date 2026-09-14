import { notFound } from "next/navigation";
import { TerminalPrompt } from "@/components/terminal/TerminalPrompt";
import { createClient } from "@/lib/supabase/server";
import { ScanLiveView } from "./ScanLiveView";

export default async function ScanDetailPage({
  params,
}: {
  params: Promise<{ id: string; projectId: string; scanId: string }>;
}) {
  const { scanId } = await params;
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
      <TerminalPrompt path="~/scan" className="text-lg" />
      <ScanLiveView
        scanId={scanId}
        initialScan={scan}
        initialLogs={logs ?? []}
        initialFindings={findings ?? []}
      />
    </div>
  );
}
