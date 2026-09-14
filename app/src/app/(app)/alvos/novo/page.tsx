import { TerminalPrompt } from "@/components/terminal/TerminalPrompt";
import { TerminalWindow } from "@/components/terminal/TerminalWindow";
import { TargetForm } from "./TargetForm";

export default function NewTargetPage() {
  return (
    <div className="flex flex-1 flex-col gap-4">
      <TerminalPrompt path="~/alvos/novo" className="text-lg" />
      <TerminalWindow title="user@sentinela:~/alvos/novo$" accent="phosphor" className="max-w-lg">
        <TargetForm />
      </TerminalWindow>
    </div>
  );
}
