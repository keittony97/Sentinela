import { Document, Page, Text, View, StyleSheet } from "@react-pdf/renderer";
import type { Tables } from "@/lib/supabase/database.types";

type Severity = Tables<"findings">["severity"];

const SEVERITY_ORDER: Severity[] = ["critico", "alto", "medio", "baixo", "informativo"];

const SEVERITY_LABEL: Record<Severity, string> = {
  critico: "CRÍTICO",
  alto: "ALTO",
  medio: "MÉDIO",
  baixo: "BAIXO",
  informativo: "INFORMATIVO",
};

const SEVERITY_COLOR: Record<Severity, string> = {
  critico: "#d92626",
  alto: "#c76a12",
  medio: "#a3810b",
  baixo: "#1f8f4a",
  informativo: "#1a7aa8",
};

const LEGAL_MODE_LABEL: Record<string, string> = {
  verificacao_externa: "Verificação Externa (Legal)",
  ambiente_teste: "Ambiente de Teste (autorizado)",
};

const AUTH_MODE_LABEL: Record<string, string> = {
  sem_login: "Sem login",
  com_login: "Com login",
};

const styles = StyleSheet.create({
  coverPage: {
    backgroundColor: "#060a07",
    color: "#baffc9",
    padding: 48,
    display: "flex",
    flexDirection: "column",
    justifyContent: "center",
    height: "100%",
  },
  coverBrand: {
    fontSize: 14,
    color: "#39ff6a",
    marginBottom: 4,
    fontFamily: "Courier-Bold",
  },
  coverTitle: {
    fontSize: 26,
    fontFamily: "Helvetica-Bold",
    marginTop: 24,
    marginBottom: 12,
  },
  coverSubtitle: {
    fontSize: 13,
    color: "#6fa87e",
    marginBottom: 40,
  },
  coverMetaRow: {
    flexDirection: "row",
    marginBottom: 6,
  },
  coverMetaLabel: {
    fontSize: 10,
    color: "#6fa87e",
    width: 140,
  },
  coverMetaValue: {
    fontSize: 10,
    color: "#baffc9",
  },
  page: {
    padding: 36,
    fontSize: 10,
    fontFamily: "Helvetica",
    color: "#1a1a1a",
  },
  h1: {
    fontSize: 16,
    fontFamily: "Helvetica-Bold",
    marginBottom: 12,
    color: "#0a2e17",
  },
  h2: {
    fontSize: 12,
    fontFamily: "Helvetica-Bold",
    marginTop: 16,
    marginBottom: 6,
    color: "#0a2e17",
  },
  paragraph: {
    fontSize: 10,
    lineHeight: 1.5,
    marginBottom: 6,
  },
  summaryTable: {
    marginTop: 8,
    marginBottom: 12,
  },
  summaryRow: {
    flexDirection: "row",
    borderBottomWidth: 1,
    borderBottomColor: "#e0e0e0",
    paddingVertical: 4,
  },
  summaryCellLabel: {
    width: 140,
    fontSize: 10,
  },
  summaryCellValue: {
    fontSize: 10,
    fontFamily: "Helvetica-Bold",
  },
  severityChip: {
    fontSize: 8,
    fontFamily: "Helvetica-Bold",
    color: "#ffffff",
    paddingVertical: 2,
    paddingHorizontal: 6,
    borderRadius: 2,
    width: 70,
    textAlign: "center",
  },
  findingBlock: {
    marginBottom: 14,
    paddingBottom: 10,
    borderBottomWidth: 1,
    borderBottomColor: "#eeeeee",
  },
  findingHeaderRow: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    marginBottom: 4,
  },
  findingTitle: {
    fontSize: 11,
    fontFamily: "Helvetica-Bold",
    flex: 1,
    marginRight: 8,
  },
  findingMeta: {
    fontSize: 8,
    color: "#666666",
    marginBottom: 4,
  },
  findingLabel: {
    fontSize: 9,
    fontFamily: "Helvetica-Bold",
    marginTop: 4,
  },
  findingText: {
    fontSize: 9,
    lineHeight: 1.4,
    color: "#333333",
  },
  evidenceBlock: {
    fontFamily: "Courier",
    fontSize: 7.5,
    backgroundColor: "#f4f4f4",
    padding: 6,
    marginTop: 3,
    color: "#333333",
  },
  remediationRow: {
    flexDirection: "row",
    borderBottomWidth: 1,
    borderBottomColor: "#e0e0e0",
    paddingVertical: 5,
    alignItems: "flex-start",
  },
  remediationIndex: {
    width: 20,
    fontSize: 9,
    fontFamily: "Helvetica-Bold",
  },
  remediationSeverity: {
    width: 75,
  },
  remediationBody: {
    flex: 1,
  },
  remediationTitle: {
    fontSize: 9,
    fontFamily: "Helvetica-Bold",
    marginBottom: 2,
  },
  remediationAction: {
    fontSize: 8.5,
    color: "#444444",
  },
  footer: {
    position: "absolute",
    bottom: 20,
    left: 36,
    right: 36,
    fontSize: 7,
    color: "#999999",
    textAlign: "center",
  },
});

function SeverityChip({ severity }: { severity: Severity }) {
  return (
    <Text style={[styles.severityChip, { backgroundColor: SEVERITY_COLOR[severity] }]}>
      {SEVERITY_LABEL[severity]}
    </Text>
  );
}

// Texto padrão, só usado se a organização ainda não tiver configurado o
// próprio template em report_compliance_templates (ex: org criada depois
// dessa migração, sem seed). O texto de verdade fica no banco.
const DEFAULT_METHODOLOGY_STATEMENT =
  "Este relatório documenta os resultados de uma verificação de segurança conduzida estritamente sob a modalidade legal declarada para o projeto ({{modalidade}}). Nenhum procedimento intrusivo ou exploratório foi realizado além do estritamente necessário para confirmar a existência de cada vulnerabilidade relatada — não houve extração, cópia ou manipulação de dados além do mínimo indispensável para evidenciar a falha encontrada.";

const DEFAULT_LGPD_NOTE =
  "Nota de conformidade com a LGPD (Lei nº 13.709/2018): esta verificação pode ter exposto, incidentalmente, dados pessoais durante a confirmação de vulnerabilidades (art. 6º — princípios da necessidade e da minimização, e art. 46 — medidas de segurança exigidas do controlador/operador). Qualquer dado pessoal eventualmente visualizado durante o teste foi tratado exclusivamente para fins de confirmação e documentação da falha identificada, sem armazenamento além do estritamente necessário para a elaboração deste relatório. Como recomendação técnica — não como afirmação jurídica categórica — sugere-se que a organização responsável pelo alvo avalie, junto ao seu Encarregado de Dados (DPO) e à área jurídica, a eventual necessidade de comunicação à Autoridade Nacional de Proteção de Dados (ANPD) e aos titulares dos dados, conforme art. 48 da LGPD.";

export type ProjectReportProps = {
  organizationName: string;
  target: { name: string; url: string; scope: string };
  project: {
    name: string;
    auth_mode: string;
    legal_mode: string;
    authorization_reference: string | null;
    authorization_justification: string | null;
    created_at: string;
  };
  scans: Array<{
    id: string;
    tools_used: string[];
    status: string;
    created_at: string;
    started_at: string | null;
    finished_at: string | null;
    triggered_by_username: string | null;
    triggered_by_role: string | null;
  }>;
  findings: Array<Tables<"findings">>;
  generatedAt: string;
  complianceTemplate: { methodology_statement: string; lgpd_note: string } | null;
  involvesPersonalData: boolean;
};

export function ProjectReportDocument({
  organizationName,
  target,
  project,
  scans,
  findings,
  generatedAt,
  complianceTemplate,
  involvesPersonalData,
}: ProjectReportProps) {
  const sortedFindings = [...findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );
  const counts = SEVERITY_ORDER.reduce<Record<Severity, number>>(
    (acc, sev) => {
      acc[sev] = findings.filter((f) => f.severity === sev).length;
      return acc;
    },
    { critico: 0, alto: 0, medio: 0, baixo: 0, informativo: 0 },
  );

  const methodologyText = (complianceTemplate?.methodology_statement ?? DEFAULT_METHODOLOGY_STATEMENT).replace(
    "{{modalidade}}",
    LEGAL_MODE_LABEL[project.legal_mode] ?? project.legal_mode,
  );
  const lgpdText = complianceTemplate?.lgpd_note ?? DEFAULT_LGPD_NOTE;
  const toolsUsed = Array.from(new Set(scans.flatMap((s) => s.tools_used)));

  return (
    <Document
      title={`Sentinela - Relatorio - ${project.name}`}
      author="Sentinela"
      subject={`Relatorio de verificacao de seguranca - ${target.name}`}
    >
      {/* Capa */}
      <Page size="A4" style={styles.coverPage}>
        <Text style={styles.coverBrand}>sentinela@{organizationName}:~$</Text>
        <Text style={styles.coverTitle}>Relatório de Verificação de Segurança</Text>
        <Text style={styles.coverSubtitle}>PENTEST &amp; BUG BOUNTY</Text>

        <View style={styles.coverMetaRow}>
          <Text style={styles.coverMetaLabel}>Alvo</Text>
          <Text style={styles.coverMetaValue}>{target.name}</Text>
        </View>
        <View style={styles.coverMetaRow}>
          <Text style={styles.coverMetaLabel}>URL</Text>
          <Text style={styles.coverMetaValue}>{target.url}</Text>
        </View>
        <View style={styles.coverMetaRow}>
          <Text style={styles.coverMetaLabel}>Escopo</Text>
          <Text style={styles.coverMetaValue}>
            {target.scope === "internet" ? "Internet (público)" : "Intranet (rede interna/VPN)"}
          </Text>
        </View>
        <View style={styles.coverMetaRow}>
          <Text style={styles.coverMetaLabel}>Projeto</Text>
          <Text style={styles.coverMetaValue}>{project.name}</Text>
        </View>
        <View style={styles.coverMetaRow}>
          <Text style={styles.coverMetaLabel}>Autenticação</Text>
          <Text style={styles.coverMetaValue}>{AUTH_MODE_LABEL[project.auth_mode]}</Text>
        </View>
        <View style={styles.coverMetaRow}>
          <Text style={styles.coverMetaLabel}>Modalidade legal</Text>
          <Text style={styles.coverMetaValue}>{LEGAL_MODE_LABEL[project.legal_mode]}</Text>
        </View>
        <View style={styles.coverMetaRow}>
          <Text style={styles.coverMetaLabel}>Scans incluídos</Text>
          <Text style={styles.coverMetaValue}>{scans.length}</Text>
        </View>
        <View style={styles.coverMetaRow}>
          <Text style={styles.coverMetaLabel}>Gerado em</Text>
          <Text style={styles.coverMetaValue}>{generatedAt}</Text>
        </View>
      </Page>

      {/* Cabeçalho de conformidade e rastreabilidade — obrigatório em todo
          relatório (ver CLAUDE.md). Gerado a partir dos dados do(s) scan(s)
          incluído(s); texto de metodologia/LGPD vem de
          report_compliance_templates (configurável por organização). */}
      <Page size="A4" style={styles.page}>
        <Text style={styles.h1}>Conformidade e rastreabilidade</Text>

        <Text style={styles.h2}>Responsável técnico</Text>
        {scans.map((scan, idx) => (
          <Text key={scan.id} style={styles.paragraph}>
            {idx + 1}. {scan.triggered_by_username ?? "usuário removido"}
            {scan.triggered_by_role ? ` (${scan.triggered_by_role})` : ""} — período:{" "}
            {scan.started_at ? new Date(scan.started_at).toLocaleString("pt-BR") : "—"} até{" "}
            {scan.finished_at ? new Date(scan.finished_at).toLocaleString("pt-BR") : "em andamento"}
          </Text>
        ))}

        <Text style={styles.h2}>Ferramentas utilizadas</Text>
        <Text style={styles.paragraph}>
          {toolsUsed.length > 0 ? toolsUsed.join(", ") : "Nenhuma ferramenta registrada."}
        </Text>

        <Text style={styles.h2}>Declaração de metodologia e limites</Text>
        <Text style={styles.paragraph}>{methodologyText}</Text>

        {involvesPersonalData && (
          <>
            <Text style={styles.h2}>Nota de conformidade com a LGPD</Text>
            <Text style={styles.paragraph}>{lgpdText}</Text>
          </>
        )}

        <Text style={styles.footer} render={({ pageNumber, totalPages }) => `${pageNumber} / ${totalPages}`} fixed />
      </Page>

      {/* Sumário executivo */}
      <Page size="A4" style={styles.page}>
        <Text style={styles.h1}>Sumário executivo</Text>
        <Text style={styles.paragraph}>
          Este relatório consolida os achados de {scans.length} verificação(ões) executada(s)
          sobre o alvo &quot;{target.name}&quot; ({target.url}), no projeto &quot;{project.name}
          &quot;, sob a modalidade legal &quot;{LEGAL_MODE_LABEL[project.legal_mode]}&quot;.
          {project.legal_mode === "ambiente_teste" && project.authorization_justification && (
            <> Autorização registrada: {project.authorization_justification}
            {project.authorization_reference ? ` (ref: ${project.authorization_reference})` : ""}.</>
          )}
        </Text>

        <Text style={styles.h2}>Achados por severidade</Text>
        <View style={styles.summaryTable}>
          {SEVERITY_ORDER.map((sev) => (
            <View key={sev} style={styles.summaryRow}>
              <View style={{ width: 90 }}>
                <SeverityChip severity={sev} />
              </View>
              <Text style={styles.summaryCellValue}>{counts[sev]}</Text>
            </View>
          ))}
          <View style={[styles.summaryRow, { borderBottomWidth: 0 }]}>
            <Text style={styles.summaryCellLabel}>Total</Text>
            <Text style={styles.summaryCellValue}>{findings.length}</Text>
          </View>
        </View>

        <Text style={styles.h2}>Verificações incluídas neste relatório</Text>
        {scans.map((scan, idx) => (
          <Text key={scan.id} style={styles.paragraph}>
            {idx + 1}. {scan.tools_used.join(", ")} — status: {scan.status} — executado em{" "}
            {new Date(scan.created_at).toLocaleString("pt-BR")}
          </Text>
        ))}

        <Text style={styles.footer} render={({ pageNumber, totalPages }) => `${pageNumber} / ${totalPages}`} fixed />
      </Page>

      {/* Detalhamento técnico */}
      <Page size="A4" style={styles.page} wrap>
        <Text style={styles.h1}>Detalhamento técnico</Text>
        {sortedFindings.length === 0 && (
          <Text style={styles.paragraph}>Nenhum achado registrado nas verificações incluídas.</Text>
        )}
        {sortedFindings.map((finding, idx) => (
          <View key={finding.id} style={styles.findingBlock} wrap={false}>
            <View style={styles.findingHeaderRow}>
              <Text style={styles.findingTitle}>
                {idx + 1}. {finding.title}
              </Text>
              <SeverityChip severity={finding.severity} />
            </View>
            <Text style={styles.findingMeta}>
              {[finding.cwe, finding.owasp_category].filter(Boolean).join(" · ") || "sem CWE/OWASP associado"}
            </Text>

            {finding.description && (
              <>
                <Text style={styles.findingLabel}>Como foi encontrada</Text>
                <Text style={styles.findingText}>{finding.description}</Text>
              </>
            )}
            {finding.impact && (
              <>
                <Text style={styles.findingLabel}>Impacto</Text>
                <Text style={styles.findingText}>{finding.impact}</Text>
              </>
            )}
            {finding.recommendation && (
              <>
                <Text style={styles.findingLabel}>Como corrigir</Text>
                <Text style={styles.findingText}>{finding.recommendation}</Text>
              </>
            )}
            {finding.reference_links && finding.reference_links.length > 0 && (
              <>
                <Text style={styles.findingLabel}>Referências</Text>
                <Text style={styles.findingText}>{finding.reference_links.join(", ")}</Text>
              </>
            )}
            {finding.evidence && Object.keys(finding.evidence as object).length > 0 && (
              <>
                <Text style={styles.findingLabel}>Evidência</Text>
                <Text style={styles.evidenceBlock}>
                  {JSON.stringify(finding.evidence, null, 2).slice(0, 800)}
                </Text>
              </>
            )}
          </View>
        ))}

        <Text style={styles.footer} render={({ pageNumber, totalPages }) => `${pageNumber} / ${totalPages}`} fixed />
      </Page>

      {/* Plano de remediação priorizado */}
      <Page size="A4" style={styles.page} wrap>
        <Text style={styles.h1}>Plano de remediação priorizado</Text>
        <Text style={styles.paragraph}>
          Ordem sugerida de correção — do maior risco para o menor. Achados informativos ficam
          por último e podem não exigir ação imediata.
        </Text>
        {sortedFindings.map((finding, idx) => (
          <View key={finding.id} style={styles.remediationRow} wrap={false}>
            <Text style={styles.remediationIndex}>{idx + 1}.</Text>
            <View style={styles.remediationSeverity}>
              <SeverityChip severity={finding.severity} />
            </View>
            <View style={styles.remediationBody}>
              <Text style={styles.remediationTitle}>{finding.title}</Text>
              <Text style={styles.remediationAction}>
                {finding.recommendation || "Sem recomendação registrada."}
              </Text>
            </View>
          </View>
        ))}

        <Text style={styles.footer} render={({ pageNumber, totalPages }) => `${pageNumber} / ${totalPages}`} fixed />
      </Page>
    </Document>
  );
}
