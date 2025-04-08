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

  console.log('Received client_id:', client_id);
  console.log('Received redirect_uri:', redirect_uri);
  console.log('Received scope:', scope);
  console.log('Received state:', state);
  console.log('Received response_type:', response_type);
  console.log('Received code_challenge:', code_challenge);
  console.log('Received code_challenge_method:', code_challenge_method);

  if (response_type !== 'code') {
    console.log('Validation failed: Unsupported response_type');
    return NextResponse.json({ error: 'Unsupported response_type' }, { status: 400 });
  }

  if (client_id !== process.env.CLIENT_ID) {
    console.log('Validation failed: Invalid client_id');
    return NextResponse.json({ error: 'Invalid client_id' }, { status: 400 });
  }

  if (code_challenge && code_challenge_method !== 'S256') {
    console.log('Validation failed: Unsupported code_challenge_method');
    return NextResponse.json({ error: 'Unsupported code_challenge_method' }, { status: 400 });
  }

  const redirectUrl = new URL('/login', req.url);
  redirectUrl.searchParams.set('client_id', client_id || '');
  redirectUrl.searchParams.set('redirect_uri', redirect_uri || '');
  redirectUrl.searchParams.set('scope', scope || '');
  redirectUrl.searchParams.set('state', state || '');
  redirectUrl.searchParams.set('response_type', response_type || '');
  redirectUrl.searchParams.set('code_challenge', code_challenge || '');
  redirectUrl.searchParams.set('code_challenge_method', code_challenge_method || '');

  console.log('Redirecting to:', redirectUrl.toString());
  return NextResponse.redirect(redirectUrl);
}

export async function POST(req: NextRequest) {
  const body = await req.json();
  const { client_id, redirect_uri, scope, state, response_type, code_challenge, code_challenge_method, user } = body;

  console.log('Received client_id:', client_id);
  console.log('Received redirect_uri:', redirect_uri);
  console.log('Received scope:', scope);
  console.log('Received state:', state);
  console.log('Received response_type:', response_type);
  console.log('Received code_challenge:', code_challenge);
  console.log('Received code_challenge_method:', code_challenge_method);
  console.log('Received user:', user);

  if (response_type !== 'code') {
    console.log('Validation failed: Unsupported response_type');
    return NextResponse.json({ error: 'Unsupported response_type' }, { status: 400 });
  }

  if (client_id !== process.env.CLIENT_ID) {
    console.log('Validation failed: Invalid client_id');
    return NextResponse.json({ error: 'Invalid client_id' }, { status: 400 });
  }

  if (code_challenge && code_challenge_method !== 'S256') {
    console.log('Validation failed: Unsupported code_challenge_method');
    return NextResponse.json({ error: 'Unsupported code_challenge_method' }, { status: 400 });
  }

  if (!process.env.PRIVATE_KEY) {
    console.error('PRIVATE_KEY is not set in environment variables');
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }

  // 导入私钥
  const privateKey = await importPKCS8(process.env.PRIVATE_KEY, 'RS256');

  const code = await new SignJWT({ user, code_challenge })
    .setProtectedHeader({ alg: 'RS256' })
    .setExpirationTime('10m')
    .sign(privateKey);

  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set('code', code);
  redirectUrl.searchParams.set('state', state);

  console.log('Generated redirectUrl:', redirectUrl.toString());
  return NextResponse.json({ redirectUrl: redirectUrl.toString() });
}