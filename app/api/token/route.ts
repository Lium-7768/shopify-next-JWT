import { SignJWT, jwtVerify } from 'jose';
import { createSecretKey, createHash } from 'crypto';
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

export async function POST(req: NextRequest) {
  const { grant_type, code, redirect_uri, client_id, client_secret, code_verifier } = await req.json();

  if (grant_type !== 'authorization_code') {
    return NextResponse.json({ error: 'Unsupported grant_type' }, { status: 400 });
  }

  console.log('Environment CLIENT_ID:', process.env.CLIENT_ID);
  console.log('Environment CLIENT_SECRET:', process.env.CLIENT_SECRET);
  console.log('Received client_id:', client_id);
  console.log('Received client_secret:', client_secret);

  if (client_id !== process.env.CLIENT_ID || client_secret !== process.env.CLIENT_SECRET) {
    console.log('Validation failed: Invalid client credentials');
    return NextResponse.json({ error: 'Invalid client credentials' }, { status: 400 });
  }

  const secret = createSecretKey(process.env.JWT_SECRET || 'dGhpcy1pcy1hLXNlY3VyZS1zZWNyZXQtZm9yLWp3dC1zaWduaW5n', 'utf-8');
  let authData: AuthData;
  try {
    const { payload } = await jwtVerify(code, secret, { algorithms: ['HS256'] });
    authData = payload as AuthData;
  } catch (error) {
    return NextResponse.json({ error: 'Invalid or expired code' }, { status: 400 });
  }

  if (authData.code_challenge) {
    if (!code_verifier) {
      return NextResponse.json({ error: 'Missing code_verifier' }, { status: 400 });
    }
    const verifierHash = createHash('sha256').update(code_verifier).digest('base64url');
    if (verifierHash !== authData.code_challenge) {
      return NextResponse.json({ error: 'Invalid code_verifier' }, { status: 400 });
    }
  }

  const accessToken = await new SignJWT({ sub: authData.user.id })
    .setProtectedHeader({ alg: 'HS256' })
    .setExpirationTime('1h')
    .sign(secret);

  const idToken = await new SignJWT({
    sub: authData.user.id,
    email: authData.user.email,
    iss: 'https://shopify-next-jwt.vercel.app',
    aud: client_id,
    exp: Math.floor(Date.now() / 1000) + 3600,
  })
    .setProtectedHeader({ alg: 'HS256' })
    .sign(secret);

  return NextResponse.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 3600,
    id_token: idToken,
  });
}