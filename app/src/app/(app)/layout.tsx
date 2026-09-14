import { AppHeader } from "@/components/app/AppHeader";
import { requireUser } from "@/lib/supabase/auth";

export default async function AppLayout({ children }: { children: React.ReactNode }) {
  const session = await requireUser();

  return (
    <div className="flex flex-1 flex-col">
      <AppHeader session={session} />
      <main className="flex flex-1 flex-col px-4 py-6 sm:px-8 sm:py-8">{children}</main>
    </div>
  );
}
