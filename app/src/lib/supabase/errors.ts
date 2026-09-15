export function friendlyDbError(message: string): string {
  if (message.includes("row-level security")) {
    return "Sem permissão para esta ação — verifique seu papel (role) e se o MFA está habilitado.";
  }
  if (message.includes("chk_ambiente_teste_autorizado")) {
    return 'Modalidade "Ambiente de Teste" exige autorização confirmada e justificativa.';
  }
  if (message.includes("Ferramentas ativas só podem ser executadas")) {
    return message;
  }
  if (message.includes("Ferramentas de exploração confirmatória")) {
    return message;
  }
  return message;
}
