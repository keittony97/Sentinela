"""Confiança de TLS via store de certificados do SO.

Em redes corporativas com proxy TLS próprio (certificado autoassinado na
cadeia — é o caso da rede onde este projeto foi desenvolvido), o bundle
da certifi não confia na CA da empresa e qualquer chamada HTTPS falha com
CERTIFICATE_VERIFY_FAILED. truststore faz o `ssl` do Python usar a store
de certificados do SO (igual o `curl` já faz nativamente, e igual o
`--use-system-ca` do Node no app/), sem desabilitar a verificação TLS.

`inject_into_ssl()` é idempotente e afeta o processo inteiro — importe
este módulo (`import net`) em qualquer arquivo que faça requisições HTTPS
diretamente, mesmo que outro módulo já importado no processo também
tenha feito isso. Não depender de ordem de import entre arquivos.
"""

import truststore

truststore.inject_into_ssl()
