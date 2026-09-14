import { TerminalPrompt } from "@/components/terminal/TerminalPrompt";
import { TerminalWindow } from "@/components/terminal/TerminalWindow";
import { requireUser } from "@/lib/supabase/auth";
import { MfaEnroll } from "./MfaEnroll";

export default async function MfaPage() {
  const session = await requireUser();

  return (
    <div className="flex flex-1 flex-col gap-4">
      <TerminalPrompt path="~/mfa" className="text-lg" />
      <TerminalWindow title="user@sentinela:~/mfa$" accent="amber" className="max-w-lg">
        <MfaEnroll alreadyVerified={session.mfaCurrentLevel === "aal2"} />
      </TerminalWindow>
    </div>
  );
}
