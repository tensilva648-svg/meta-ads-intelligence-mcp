# Deploy rápido

## 1. GitHub

Crie um repositório privado e envie estes arquivos. NÃO envie `.env`.

## 2. Hospedagem

Use um serviço que entregue uma URL HTTPS pública e permita variáveis de ambiente. Render, Railway, Fly.io, Cloud Run e similares funcionam.

Com Docker, use o `Dockerfile`.

Variáveis obrigatórias:
- MCP_BEARER_TOKEN
- META_ACCESS_TOKEN
- META_AD_ACCOUNT_ID
- META_API_VERSION

Opcional:
- META_AD_LIBRARY_COUNTRY=BR
- ALLOW_MUTATIONS=false
- MAX_BULK_MUTATIONS=50

## 3. Teste

Abra:
https://SEU-DOMINIO/health

Deve responder JSON com `ok: true`.

## 4. Claude

No Claude:
Personalizar > Conectores > + > Adicionar conector personalizado.

Nome:
Meta Ads Intelligence

URL:
https://SEU-DOMINIO/mcp

ATENÇÃO:
A versão inicial usa Bearer Token para proteção. A interface do Claude pode exigir OAuth para conexões remotas autenticadas. Para produção, implemente OAuth 2.1/PKCE ou coloque o MCP atrás de um gateway de autenticação compatível com o fluxo de conectores do Claude. Não deixe um servidor Meta Ads sem autenticação na internet.

## 5. Segurança de produção

- deixe `ALLOW_MUTATIONS=false` até validar leitura;
- limite a quantidade de mutações por lote;
- use HTTPS;
- mantenha o token da Meta somente como secret do servidor;
- use um token Meta com o menor conjunto de permissões necessário;
- registre auditoria de alterações;
- faça backup/export antes de alterações em massa.

## Roadmap v0.3

- OAuth 2.1/PKCE para conexão nativa com Claude;
- banco de dados de histórico;
- cache e rate-limit;
- filas para lotes;
- rollback;
- análise de criativos;
- relatório diário;
- monitoramento de concorrentes com fontes públicas/autorizadas;
- comparação automática de copies;
- aprovação humana obrigatória antes de alterações em massa.
