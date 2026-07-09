import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";

function loginErrorRedirect(request: NextRequest, message: string) {
  const url = new URL("/login", "http://local");
  url.searchParams.set("error", message);
  return new NextResponse(null, {
    status: 303,
    headers: { Location: `${url.pathname}${url.search}` },
  });
}

export async function POST(request: NextRequest) {
  let supabaseResponse = NextResponse.next();

  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        getAll() {
          return request.cookies.getAll();
        },
        setAll(cookiesToSet) {
          cookiesToSet.forEach(({ name, value }) =>
            request.cookies.set(name, value),
          );
          supabaseResponse = NextResponse.next();
          cookiesToSet.forEach(({ name, value, options }) =>
            supabaseResponse.cookies.set(name, value, options),
          );
        },
      },
    },
  );

  const formData = await request.formData();
  const email = String(formData.get("email") ?? "").trim();
  const password = String(formData.get("password") ?? "");
  const inviteToken = String(formData.get("invite") ?? "").trim();

  if (!email || !password) {
    return loginErrorRedirect(request, "Email and password are required");
  }

  const { error } = await supabase.auth.signInWithPassword({
    email,
    password,
  });

  if (error) {
    return loginErrorRedirect(request, error.message);
  }

  const redirectTo = inviteToken
    ? `/join/${encodeURIComponent(inviteToken)}`
    : "/dashboard";

  const redirect = new NextResponse(null, {
    status: 303,
    headers: { Location: redirectTo },
  });
  supabaseResponse.cookies.getAll().forEach((cookie) => {
    redirect.cookies.set(cookie);
  });
  redirect.headers.set("Cache-Control", "no-store");
  return redirect;
}
