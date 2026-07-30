# Migrations SolanoSolutions

Este manifesto registra as migrations criadas pela SolanoSolutions.

As migrations executáveis permanecem diretamente em `supabase/migrations` e
usam o prefixo `ss_` após o timestamp ou número sequencial, garantindo que a
Supabase CLI consiga descobri-las.

| Migration | Contexto | Backlog | Validação local | Staging | Produção |
|---|---|---|---|---|---|
| `027_ss_security_grants_and_function_hardening.sql` | Grants mínimos e restrição de funções privilegiadas | CRM-SS-015, CRM-SS-016 | Validada em 30/07/2026 | Aplicada em 30/07/2026 | Não autorizado |
| `028_ss_function_execute_allowlist.sql` | Correção das ACLs explícitas criadas pelo bootstrap Supabase | CRM-SS-015, CRM-SS-016 | Validada em 30/07/2026 | Aplicada em 30/07/2026 | Não autorizado |

Produção somente pode ser preenchida como aplicada após autorização explícita do
usuário.
