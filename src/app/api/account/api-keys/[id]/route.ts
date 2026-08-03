// ============================================================
// DELETE /api/account/api-keys/[id] — revoke a key.
//
// Soft revoke: sets `revoked_at` rather than deleting the row, so
// the key's name/prefix stay visible in the roster as an audit
// trail ("this key existed and was turned off") and so the auth
// path's liveness check (`findActiveKeyByHash` filters revoked
// rows) starts rejecting it immediately. Admin+, enforced here and
// again inside the narrowly scoped revocation RPC.
//
// Revocation is effective on the next request: once `revoked_at` is
// set, `findActiveKeyByHash` returns null and the key 401s.
// ============================================================

import { NextResponse } from 'next/server';

import { requireRole, toErrorResponse } from '@/lib/auth/account';
import {
  checkRateLimit,
  rateLimitResponse,
  RATE_LIMITS,
} from '@/lib/rate-limit';

export async function DELETE(
  _request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const ctx = await requireRole('admin');

    const limit = checkRateLimit(
      `admin:apiKeyRevoke:${ctx.userId}`,
      RATE_LIMITS.adminAction
    );
    if (!limit.success) return rateLimitResponse(limit);

    const { id } = await params;

    // The RPC scopes by account_id and only transitions NULL -> timestamp,
    // so a direct client cannot revoke another account's key or reactivate one.
    const { data, error } = await ctx.supabase.rpc('revoke_account_api_key', {
      p_account_id: ctx.accountId,
      p_key_id: id,
    });

    if (error) {
      console.error(
        '[DELETE /api/account/api-keys/[id]] revocation failed:',
        error.code
      );
      return NextResponse.json(
        { error: 'Failed to revoke API key' },
        { status: 500 }
      );
    }
    if (data !== true) {
      // Either no such key in this account, or it was already revoked.
      return NextResponse.json(
        { error: 'API key not found or already revoked' },
        { status: 404 }
      );
    }

    return NextResponse.json({ success: true });
  } catch (err) {
    return toErrorResponse(err);
  }
}
