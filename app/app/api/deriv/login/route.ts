
import { createHash, randomBytes } from "node:crypto";
import { NextResponse } from "next/server";

export const runtime = "nodejs";

export async function GET() {
  const appId = process.env.DERIV_APP_ID;
  const siteUrl = process.env.NEXT_PUBLIC_SITE_URL;

  if (!appId || !siteUrl) {
    return NextResponse.json(
      { error: "Deriv OAuth is not configured." },
      { status: 500 }
    );
  }

  const redirectUri = `${siteUrl}/api/deriv/callback`;
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256")
    .update(verifier)
    .digest("base64url");
  const state = randomBytes(32).toString("base64url");

  const url = new URL("https://auth.deriv.com/oauth2/auth");
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", appId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("scope", "trade");
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", challenge);
  url.searchParams.set("code_challenge_method", "S256");

  const response = NextResponse.redirect(url);

  const cookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax" as const,
    path: "/api/deriv",
    maxAge: 600,
  };

  response.cookies.set("deriv_pkce_verifier", verifier, cookieOptions);
  response.cookies.set("deriv_oauth_state", state, cookieOptions);

  return response;
}
  
