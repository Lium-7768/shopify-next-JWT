import { SignJWT, importPKCS8 } from 'jose';
import { NextRequest, NextResponse } from 'next/server';

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const client_id = searchParams.get('client_id');
  const redirect_uri = searchParams.get('redirect_uri');
  const scope = searchParams.get('scope');
  const state = searchParams.get('state');
  const response_type = searchParams.get('response_type');
  const code_challenge = searchParams.get('code_challenge');
  const code_challenge_method = searchParams.get('code_challenge_method');

  if (response_type !== 'code') {
    return NextResponse.json({ error: 'unsupported_response_type' }, { status: 400 });
  }

  if (client_id !== process.env.CLIENT_ID) {
    return NextResponse.json({ error: 'unauthorized_client' }, { status: 401 });
  }

  if (!redirect_uri?.startsWith('https://shopify.com/authentication/')) {
    return NextResponse.json({ error: 'invalid_request' }, { status: 400 });
  }

  if (code_challenge && code_challenge_method !== 'S256') {
    return NextResponse.json({ error: 'invalid_request' }, { status: 400 });
  }

  const redirectUrl = new URL('/login', req.url);
  redirectUrl.searchParams.set('client_id', client_id || '');
  redirectUrl.searchParams.set('redirect_uri', redirect_uri || '');
  redirectUrl.searchParams.set('scope', scope || '');
  redirectUrl.searchParams.set('state', state || '');
  redirectUrl.searchParams.set('response_type', response_type || '');
  if (code_challenge) {
    redirectUrl.searchParams.set('code_challenge', code_challenge);
    redirectUrl.searchParams.set('code_challenge_method', code_challenge_method || '');
  }

  return NextResponse.redirect(redirectUrl);
}

export async function POST(req: NextRequest) {
  const body = await req.json();
  const {
    client_id,
    redirect_uri,
    scope,
    state,
    response_type,
    code_challenge,
    code_challenge_method,
    user
  } = body;

  if (response_type !== 'code') {
    return NextResponse.json({ error: 'unsupported_response_type' }, { status: 400 });
  }

  if (client_id !== process.env.CLIENT_ID) {
    return NextResponse.json({ error: 'unauthorized_client' }, { status: 401 });
  }

  if (!redirect_uri?.startsWith('https://shopify.com/authentication/')) {
    return NextResponse.json({ error: 'invalid_request' }, { status: 400 });
  }

  if (code_challenge && code_challenge_method !== 'S256') {
    return NextResponse.json({ error: 'invalid_request' }, { status: 400 });
  }

  if (!process.env.PRIVATE_KEY) {
    console.error('PRIVATE_KEY is not set in environment variables');
    return NextResponse.json({ error: 'server_error' }, { status: 500 });
  }

  const privateKey = await importPKCS8(process.env.PRIVATE_KEY, 'RS256');

  const code = await new SignJWT({
    user,
    code_challenge,
    scope: scope || 'openid email'
  })
    .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
    .setExpirationTime('10m')
    .sign(privateKey);

  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set('code', code);
  if (state) {
    redirectUrl.searchParams.set('state', state);
  }

  return NextResponse.json({ redirectUrl: redirectUrl.toString() });
}