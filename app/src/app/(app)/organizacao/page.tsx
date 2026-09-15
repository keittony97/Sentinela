import { TerminalPrompt } from "@/components/terminal/TerminalPrompt";
import { TerminalWindow } from "@/components/terminal/TerminalWindow";
import { requireUser } from "@/lib/supabase/auth";
import { createClient } from "@/lib/supabase/server";
import { OrganizationForm } from "./OrganizationForm";

export default async function OrganizationPage() {
  const session = await requireUser();
  const supabase = await createClient();

  const { data: organization } = await supabase
    .from("organizations")
    .select("name, contact_email")
    .eq("id", session.profile.organization_id)
    .single();

  const canEdit = session.profile.role === "admin" && session.mfaCurrentLevel === "aal2";

  return (
    <div className="flex flex-1 flex-col gap-4">
      <TerminalPrompt path="~/organizacao" className="text-lg" />
      <TerminalWindow title="user@sentinela:~/organizacao$" accent="cyan" className="max-w-lg">
        <OrganizationForm
          name={organization?.name ?? session.organizationName}
          contactEmail={organization?.contact_email ?? null}
          canEdit={canEdit}
        />
      </TerminalWindow>
    </div>
  );
}
