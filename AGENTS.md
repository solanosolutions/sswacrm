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


## Fluxo obrigatório de implementação e entrega

- Agrupe mudanças em blocos funcionais coerentes com a documentação canônica,
  o backlog e o objetivo em execução.
- Não crie commits ou checkpoints para alterações isoladas sem valor contextual.
- Ao concluir cada bloco:
  1. execute as validações proporcionais ao risco;
  2. atualize os checks e o status dos itens relacionados no backlog vivo;
  3. documente o comportamento efetivamente implementado em um arquivo Markdown
     na pasta temática correspondente de `project-docs`;
  4. atualize o checkpoint ativo;
  5. crie um commit contextual e envie-o para o fluxo de staging.
- A branch `develop` representa staging. A promoção para produção (`main`) somente
  pode ocorrer após autorização explícita do usuário.
- Não registre como concluído no backlog um item cujo critério de aceite ainda
  não tenha sido validado.

## Migrations SolanoSolutions

- Preserve sem reescrita as migrations herdadas do WACRM.
- Toda nova migration criada pela SolanoSolutions deve:
  - permanecer diretamente em `supabase/migrations`, para compatibilidade com a
    Supabase CLI;
  - usar o prefixo descritivo `ss_` após o timestamp ou número sequencial;
  - ser registrada em `supabase/migrations/ss/MANIFEST.md`;
  - ser validada localmente antes de staging;
  - ser aplicada em staging antes de qualquer promoção para produção.
- A pasta `supabase/migrations/ss` é documental e não deve conter migrations
  executáveis.
- Migrations destrutivas exigem estratégia de restauração ou migration corretiva
  documentada antes da aplicação.

## Retomada eficiente

Ao iniciar ou retomar uma conversa, use
`project-docs/prompts/INICIALIZACAO-CONTEXTO.md`. Comece pelo checkpoint
`project-docs/Checkpoints/CURRENT.md` e carregue somente os documentos diretamente
necessários ao próximo passo registrado.
