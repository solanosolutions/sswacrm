-- Corrective hardening for function ACLs created by the Supabase bootstrap.
--
-- A clean local/staging bootstrap grants EXECUTE directly to runtime roles on
-- newly created public functions. Normalize every function first, then restore
-- only the RPC surface required by the application.

REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public
FROM PUBLIC, anon, authenticated, service_role;

-- Public invitation preview is intentionally reachable before authentication.
GRANT EXECUTE ON FUNCTION public.peek_invitation(TEXT)
TO anon, authenticated;

-- Authenticated application RPCs.
GRANT EXECUTE ON FUNCTION public.filter_contacts_by_tags(UUID[], TEXT, INTEGER, INTEGER)
TO authenticated;
GRANT EXECUTE ON FUNCTION public.is_account_member(UUID, account_role_enum)
TO authenticated;
GRANT EXECUTE ON FUNCTION public.redeem_invitation(TEXT)
TO authenticated;
GRANT EXECUTE ON FUNCTION public.remove_account_member(UUID)
TO authenticated;
GRANT EXECUTE ON FUNCTION public.set_member_role(UUID, account_role_enum)
TO authenticated;
GRANT EXECUTE ON FUNCTION public.touch_presence(TEXT)
TO authenticated;
GRANT EXECUTE ON FUNCTION public.transfer_account_ownership(UUID)
TO authenticated;

-- Backend-only maintenance and counter RPCs.
GRANT EXECUTE ON FUNCTION public.increment_automation_execution_count(UUID)
TO service_role;
GRANT EXECUTE ON FUNCTION public.increment_flow_execution_count(UUID)
TO service_role;
GRANT EXECUTE ON FUNCTION public.is_account_member(UUID, account_role_enum)
TO service_role;
GRANT EXECUTE ON FUNCTION public.recompute_broadcast_counts(UUID)
TO service_role;
