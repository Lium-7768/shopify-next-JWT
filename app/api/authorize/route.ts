import { SignJWT } from 'jose';
import { createSecretKey } from 'crypto';
import { NextRequest, NextResponse } from 'next/server';

interface AuthData {
  user: {
    id: string;
    email: string;
  };
  code_challenge?: string;
  exp: number;
  [key: string]: any;
}

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const client_id = searchParams.get('client_id');
  const redirect_uri = searchParams.get('redirect_uri');
  const scope = searchParams.get('scope') || '';
  const state = searchParams.get('state');
  const response_type = searchParams.get('response_type');
  const code_challenge = searchParams.get('code_challenge');
  const code_challenge_method = searchParams.get('code_challenge_method');

  console.log('Environment CLIENT_ID:', process.env.CLIENT_ID);
  console.log('Received client_id:', client_id);
  console.log('Received redirect_uri:', redirect_uri);

  if (client_id !== process.env.CLIENT_ID || redirect_uri !== 'https://shopify.com/authentication/63864635466/login/external/callback') {
    console.log('Validation failed: Invalid client_id or redirect_uri');
    return NextResponse.json({ error: 'Invalid client_id or redirect_uri' }, { status: 400 });
  }

  if (response_type !== 'code') {
    return NextResponse.json({ error: 'Unsupported response_type' }, { status: 400 });
  }

  if (!scope.includes('openid') || !scope.includes('email')) {
    return NextResponse.json({ error: 'Invalid scope' }, { status: 400 });
  }

  if (code_challenge && code_challenge_method !== 'S256') {
    return NextResponse.json({ error: 'Unsupported code_challenge_method' }, { status: 400 });
  }

  const loginUrl = `/login?${searchParams.toString()}`;
  return NextResponse.redirect(new URL(loginUrl, req.url));
}

export async function POST(req: NextRequest) {
  const { client_id, redirect_uri, scope, state, response_type, code_challenge, code_challenge_method, user } = await req.json();

  console.log('Environment CLIENT_ID:', process.env.CLIENT_ID);
  console.log('Received client_id:', client_id);
  console.log('Received redirect_uri:', redirect_uri);

  if (client_id !== process.env.CLIENT_ID || redirect_uri !== 'https://shopify.com/authentication/63864635466/login/external/callback') {
    console.log('Validation failed: Invalid client_id or redirect_uri');
    return NextResponse.json({ error: 'Invalid client_id or redirect_uri' }, { status: 400 });
  }

  if (response_type !== 'code') {
    return NextResponse.json({ error: 'Unsupported response_type' }, { status: 400 });
  }

  if (!scope.includes('openid') || !scope.includes('email')) {
    return NextResponse.json({ error: 'Invalid scope' }, { status: 400 });
  }

  if (code_challenge && code_challenge_method !== 'S256') {
    return NextResponse.json({ error: 'Unsupported code_challenge_method' }, { status: 400 });
  }

  const secret = createSecretKey(process.env.JWT_SECRET || 'dGhpcy1pcy1hLXNlY3VyZS1zZWNyZXQtZm9yLWp3dC1zaWduaW5n', 'utf-8');
  const code = await new SignJWT({
    user,
    code_challenge,
    exp: Math.floor(Date.now() / 1000) + 600,
  })
    .setProtectedHeader({ alg: 'HS256' })
    .sign(secret);

  const redirectUrl = `${redirect_uri}?code=${code}&state=${state}`;
  return NextResponse.json({ redirectUrl });
}