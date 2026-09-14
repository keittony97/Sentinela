// Heurística pra decidir se a nota de conformidade LGPD entra no
// relatório. Isso NUNCA é uma análise jurídica de verdade — é um regex
// best-effort sobre título/descrição/impacto/evidência dos findings,
// procurando padrões de CPF/e-mail/telefone e palavras-chave óbvias.
// Falsos negativos são esperados (ex: um nome próprio sozinho, sem CPF
// ou e-mail junto, não é detectável por regex) — na dúvida, o time
// jurídico deve revisar o relatório de qualquer forma antes de circular.

const CPF_PATTERN = /\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b/;
const EMAIL_PATTERN = /\b[\w.+-]+@[\w-]+\.[a-z]{2,}\b/i;
const PHONE_BR_PATTERN = /\(?\d{2}\)?\s?9?\d{4}-?\d{4}\b/;

const KEYWORDS = [
  "cpf",
  "rg ",
  "nome completo",
  "dado pessoal",
  "dados pessoais",
  "dado sensível",
  "dados sensíveis",
  "cartão de crédito",
  "endereço residencial",
  "data de nascimento",
];

function textMentionsPersonalData(text: string): boolean {
  if (!text) return false;
  const lower = text.toLowerCase();
  if (KEYWORDS.some((keyword) => lower.includes(keyword))) return true;
  if (CPF_PATTERN.test(text)) return true;
  if (EMAIL_PATTERN.test(text)) return true;
  if (PHONE_BR_PATTERN.test(text)) return true;
  return false;
}

export function findingsInvolvePersonalData(
  findings: Array<{
    title: string;
    description: string | null;
    impact: string | null;
    evidence: unknown;
  }>,
): boolean {
  return findings.some((finding) => {
    const evidenceText = finding.evidence ? JSON.stringify(finding.evidence) : "";
    return [finding.title, finding.description, finding.impact, evidenceText].some((text) =>
      textMentionsPersonalData(text ?? ""),
    );
  });
}
