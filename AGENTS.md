<!-- BEGIN:nextjs-agent-rules -->
# This is NOT the Next.js you know

This version has breaking changes — APIs, conventions, and file structure may all differ from your training data. Read the relevant guide in `node_modules/next/dist/docs/` before writing any code. Heed deprecation notices.
<!-- END:nextjs-agent-rules -->

## Continuidade do projeto

Use obrigatoriamente a skill instalada `project-checkpoint` para registrar o
estado real do projeto e permitir a retomada em sessões futuras.

Acione a skill quando o usuário solicitar um checkpoint ou indicar interrupção,
encerramento ou retomada do trabalho, incluindo:

- `/checkpoint`;
- `checkpoint`;
- `crie um checkpoint`;
- `atualize o checkpoint`;
- `registre onde paramos`;
- `vamos parar por aqui`;
- `vamos continuar depois`;
- `encerre a sessão`.

Antes de encerrar qualquer sessão que tenha produzido alteração, decisão,
configuração, diagnóstico ou avanço relevante:

1. use a skill `project-checkpoint`;
2. verifique o estado atual do Git;
3. atualize o checkpoint ativo em `project-docs/Checkpoints`;
4. atualize `project-docs/Checkpoints/CURRENT.md`;
5. informe ao usuário qual checkpoint foi atualizado.

Não crie checkpoint automático quando não houver avanço real no projeto. Os
checkpoints não devem ser versionados no repositório e nunca devem registrar
segredos, credenciais, tokens ou conteúdo de arquivos `.env`.
