import { notFound } from "next/navigation";
import { TerminalPrompt } from "@/components/terminal/TerminalPrompt";
import { TerminalWindow } from "@/components/terminal/TerminalWindow";
import { createClient } from "@/lib/supabase/server";
import { ProjectForm } from "./ProjectForm";

export default async function NewProjectPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const supabase = await createClient();

  const { data: target } = await supabase.from("targets").select("id, name").eq("id", id).single();
  if (!target) notFound();

  return (
    <div className="flex flex-1 flex-col gap-4">
      <TerminalPrompt path={`~/alvos/${target.name}/projetos/novo`} className="text-lg" />
      <TerminalWindow
        title={`user@sentinela:~/alvos/${target.name}/projetos/novo$`}
        accent="amber"
        className="max-w-xl"
      >
        <ProjectForm targetId={target.id} />
      </TerminalWindow>
    </div>
  );
}
