
import { NextRequest, NextResponse } from "next/server";

export const runtime = "nodejs";

export async function GET(request: NextRequest) {
  const siteUrl = process.env.NEXT_PUBLIC_SITE_URL;
  const appId = process.env.DERIV_APP_ID;

  if (!siteUrl || !appId) {
    return NextResponse.json(
      { error: "Deriv OAuth is not configured." },
      { status: 500 }
    );
  }

  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const returnedState = url.searchParams.get("state");
  const oauthError = url.searchParams.get("error");

  const verifier = request.cookies.get("deriv_pkce_verifier")?.value;
  const savedState = request.cookies.get("deriv_oauth_state")?.value;

  const redirectUri = `${siteUrl}/api/deriv/callback`;
  const response = NextResponse.redirect(new URL("/", siteUrl));

  // Always remove one-time OAuth values after the callback.
  response.cookies.set("deriv_pkce_verifier", "", {
    path: "/api/deriv", maxAge: 0,
  });
  response.cookies.set("deriv_oauth_state", "", {
    path: "/api/deriv", maxAge: 0,
  });

  if (oauthError || !code || !returnedState || !verifier ||
      !savedState || returnedState !== savedState) {
    response.cookies.set(
      "deriv_login_error",
      "Deriv login was cancelled or could not be verified.",
      {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        path: "/",
        maxAge: 60,
      }
    );
    return response;
  }

  try {
    const tokenResponse = await fetch(
      "https://auth.deriv.com/oauth2/token",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          client_id: appId,
          code,
          code_verifier: verifier,
          redirect_uri: redirectUri,
        }),
        cache: "no-store",
      }
    );

    if (!tokenResponse.ok) {
      throw new Error("Token exchange failed");
    }

    const tokenData = await tokenResponse.json();

    if (!tokenData.access_token ||
        typeof tokenData.expires_in !== "number") {
      throw new Error("Invalid token response");
    }

    response.cookies.set(
      "deriv_access_token",
      tokenData.access_token,
      {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        path: "/",
        maxAge: Math.max(
          0,
          Math.min(tokenData.expires_in, 3600)
        ),
      }
    );

    response.cookies.set("deriv_login_error", "", {
      path: "/", maxAge: 0,
    });

    return response;
  } catch {
    response.cookies.set(
      "deriv_login_error",
      "Unable to complete Deriv login. Please try again.",
      {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        path: "/",
        maxAge: 60,
      }
    );
    return response;
  }
}
  
