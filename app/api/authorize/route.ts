import { SignJWT, importPKCS8 } from 'jose';
import { NextRequest, NextResponse } from 'next/server';
import { PRIVATE_KEY } from '@/app/constants/keys';
import crypto from 'crypto';

interface ApiError extends Error {
  message: string;
  code?: string;
}

const VALID_SCOPES = ['openid', 'profile', 'email', 'customer_read', 'customer_write'];

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const client_id = searchParams.get('client_id');
  const redirect_uri = searchParams.get('redirect_uri');
  const scope = searchParams.get('scope');
  const state = searchParams.get('state');
  const nonce = searchParams.get('nonce');
  const response_type = searchParams.get('response_type');
  const code_challenge = searchParams.get('code_challenge');
  const code_challenge_method = searchParams.get('code_challenge_method');

  console.log('GET /api/authorize - Request parameters:', {
    client_id,
    redirect_uri,
    scope,
    state,
    nonce,
    response_type,
    code_challenge,
    code_challenge_method
  });

  if (response_type !== 'code') {
    console.log('Invalid response_type:', response_type);
    return NextResponse.json({ error: 'unsupported_response_type' }, { status: 400 });
  }

  if (client_id !== process.env.CLIENT_ID) {
    console.log('Invalid client_id:', client_id);
    return NextResponse.json({ error: 'unauthorized_client' }, { status: 401 });
  }

  if (!redirect_uri?.startsWith('https://shopify.com/authentication/') || !redirect_uri.includes('/login/external/callback')) {
    console.log('Invalid redirect_uri:', redirect_uri);
    return NextResponse.json({ error: 'invalid_request' }, { status: 400 });
  }

  if (code_challenge && code_challenge_method !== 'S256') {
    console.log('Invalid code_challenge_method:', code_challenge_method);
    return NextResponse.json({ error: 'invalid_request' }, { status: 400 });
  }

  const redirectUrl = new URL('/login', req.url);
  redirectUrl.searchParams.set('client_id', client_id || '');
  redirectUrl.searchParams.set('redirect_uri', redirect_uri || '');
  redirectUrl.searchParams.set('scope', scope || '');
  redirectUrl.searchParams.set('state', state || '');
  redirectUrl.searchParams.set('nonce', nonce || '');
  redirectUrl.searchParams.set('response_type', response_type || '');
  if (code_challenge) {
    redirectUrl.searchParams.set('code_challenge', code_challenge);
    redirectUrl.searchParams.set('code_challenge_method', code_challenge_method || '');
  }

  console.log('Redirecting to:', redirectUrl.toString());
  return NextResponse.redirect(redirectUrl);
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    console.log('POST /api/authorize - Request body:', body);

    const {
      client_id,
      redirect_uri,
      scope,
      state,
      nonce,
      response_type,
      code_challenge,
      code_challenge_method,
      user
    } = body;

    if (response_type !== 'code') {
      console.log('Invalid response_type:', response_type);
      return NextResponse.json({ error: 'unsupported_response_type' }, { status: 400 });
    }

    if (client_id !== process.env.CLIENT_ID) {
      console.log('Invalid client_id:', client_id);
      return NextResponse.json({ error: 'unauthorized_client' }, { status: 401 });
    }

    if (!redirect_uri?.startsWith('https://shopify.com/authentication/') || !redirect_uri.includes('/login/external/callback')) {
      console.log('Invalid redirect_uri:', redirect_uri);
      return NextResponse.json({ error: 'invalid_request' }, { status: 400 });
    }

    if (code_challenge && code_challenge_method !== 'S256') {
      console.log('Invalid code_challenge_method:', code_challenge_method);
      return NextResponse.json({ error: 'invalid_request' }, { status: 400 });
    }

    // Validate scopes
    if (scope) {
      const requestedScopes = scope.split(' ');
      const invalidScopes = requestedScopes.filter((s: string) => !VALID_SCOPES.includes(s));
      if (invalidScopes.length > 0) {
        console.log('Invalid scopes:', invalidScopes);
        return NextResponse.json({ error: 'invalid_scope' }, { status: 400 });
      }
    }

    const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || 'https://shopify-next-jwt.vercel.app';

    console.log('Importing private key...');
    try {
      const privateKey = await importPKCS8(PRIVATE_KEY, 'RS256');
      console.log('Private key imported successfully');

      const now = Math.floor(Date.now() / 1000);

      const code = await new SignJWT({
        iss: baseUrl,
        sub: user.id,
        aud: client_id,
        exp: now + 600, // 10 minutes
        iat: now,
        auth_time: now,
        nonce: nonce,
        code_challenge,
        code_challenge_method,
        scope: scope || 'openid profile email',
        user: {
          id: user.id,
          email: user.email,
          email_verified: true,
          name: user.name || user.email.split('@')[0],
          given_name: user.given_name || '',
          family_name: user.family_name || '',
          locale: user.locale || 'en'
        }
      })
        .setProtectedHeader({ alg: 'RS256', typ: 'at+jwt', kid: '1' })
        .setJti(crypto.randomUUID())
        .setIssuedAt()
        .setExpirationTime(now + 600)
        .sign(privateKey);

      console.log('JWT code generated successfully');

      const redirectUrl = new URL(redirect_uri);
      redirectUrl.searchParams.set('code', code);
      if (state) {
        redirectUrl.searchParams.set('state', state);
      }

      console.log('Redirect URL generated:', redirectUrl.toString());
      return NextResponse.json({ redirectUrl: redirectUrl.toString() });
    } catch (error: unknown) {
      const apiError = error as ApiError;
      console.error('Error processing private key:', apiError);
      return NextResponse.json({ error: 'server_error', details: apiError.message }, { status: 500 });
    }
  } catch (error: unknown) {
    const apiError = error as ApiError;
    console.error('Unexpected error in POST /api/authorize:', apiError);
    return NextResponse.json({ error: 'server_error' }, { status: 500 });
  }
}