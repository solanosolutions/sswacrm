-- SolanoSolutions security baseline:
--   1. make Data API table grants explicit and policy-aligned;
--   2. remove PUBLIC access to internal and SECURITY DEFINER functions;
--   3. preserve only the RPC entry points required by each runtime role.
--
-- Storage and api_keys.key_hash hardening are intentionally separate blocks.

-- The Data API roles need schema visibility before object privileges apply.
GRANT USAGE ON SCHEMA public TO authenticated, service_role;

-- Supabase bootstrap roles may arrive with broad default table privileges.
-- Normalize them first so the grants below are the complete allowlist.
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public
FROM anon, authenticated, service_role;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public
FROM anon, authenticated, service_role;

-- Authenticated reads follow the existing SELECT policies. api_keys is
-- deliberately excluded until key_hash has a safe client-facing surface.
GRANT SELECT ON TABLE
  public.account_invitations,
  public.accounts,
  public.automation_logs,
  public.automation_steps,
  public.automations,
  public.broadcast_recipients,
  public.broadcasts,
  public.contact_custom_values,
  public.contact_notes,
  public.contact_tags,
  public.contacts,
  public.conversations,
  public.custom_fields,
  public.deals,
  public.flow_nodes,
  public.flow_run_events,
  public.flow_runs,
  public.flows,
  public.member_presence,
  public.message_reactions,
  public.message_templates,
  public.messages,
  public.pipeline_stages,
  public.pipelines,
  public.profiles,
  public.tags,
  public.whatsapp_config
TO authenticated;

-- Authenticated writes likewise mirror the operations exposed by RLS.
GRANT INSERT, UPDATE, DELETE ON TABLE
  public.account_invitations,
  public.automation_steps,
  public.automations,
  public.broadcast_recipients,
  public.broadcasts,
  public.contact_custom_values,
  public.contact_notes,
  public.contact_tags,
  public.contacts,
  public.conversations,
  public.custom_fields,
  public.deals,
  public.flow_nodes,
  public.flows,
  public.message_reactions,
  public.message_templates,
  public.messages,
  public.pipeline_stages,
  public.pipelines,
  public.tags,
  public.whatsapp_config
TO authenticated;

GRANT UPDATE ON TABLE public.accounts TO authenticated;
GRANT INSERT, UPDATE ON TABLE public.profiles TO authenticated;

-- Backend services use RLS-bypassing service_role, but only need CRUD—not
-- TRUNCATE, REFERENCES or TRIGGER—on application tables.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO service_role;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO service_role;

-- Trigger functions and internal broadcast helpers are never direct RPCs.
REVOKE ALL ON FUNCTION public.update_updated_at_column() FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public._bcast_bump(UUID, TEXT, INTEGER) FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public._bcast_cols_for_status(TEXT) FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.broadcast_recipient_aggregate_trigger() FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.handle_new_user() FROM PUBLIC, anon, authenticated, service_role;

-- Operational counter repair is backend-only.
REVOKE ALL ON FUNCTION public.recompute_broadcast_counts(UUID) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.recompute_broadcast_counts(UUID) TO service_role;

-- RLS helper: callable only by policies executing for authenticated/backend
-- roles. Removing PUBLIC also prevents accidental future access by anon.
REVOKE ALL ON FUNCTION public.is_account_member(UUID, account_role_enum) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.is_account_member(UUID, account_role_enum) TO authenticated, service_role;

-- Presence is the only client-facing RPC hardened in this migration.
REVOKE ALL ON FUNCTION public.touch_presence(TEXT) FROM PUBLIC, anon, service_role;
GRANT EXECUTE ON FUNCTION public.touch_presence(TEXT) TO authenticated;
