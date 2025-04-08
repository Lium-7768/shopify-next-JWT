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
  let body: any;
  let client_id: string | undefined;
  let client_secret: string | undefined;

  // 解析 Authorization 头部（Basic Auth）
  const authHeader = req.headers.get('authorization');
  console.log('Authorization Header:', authHeader);
  if (authHeader && authHeader.startsWith('Basic ')) {
    const base64Credentials = authHeader.split(' ')[1];
    const credentials = Buffer.from(base64Credentials, 'base64').toString('utf-8');
    const [id, secret] = credentials.split(':');
    client_id = id;
    client_secret = secret;
    console.log('Basic Auth client_id:', client_id);
    console.log('Basic Auth client_secret:', client_secret);
  }

  const contentType = req.headers.get('content-type') || '';
  console.log('Content-Type:', contentType);

  // 解析请求体
  if (contentType.includes('application/json')) {
    body = await req.json();
  } else if (contentType.includes('application/x-www-form-urlencoded')) {
    const formData = await req.formData();
    body = Object.fromEntries(formData);
  } else {
    console.log('Validation failed: Unsupported content type');
    return NextResponse.json({ error: 'Unsupported content type' }, { status: 400 });
  }

  console.log('Raw request body:', body);

  const { grant_type, code, redirect_uri, code_verifier } = body;

  // 如果没有从 Basic Auth 获取 client_id 和 client_secret，则尝试从请求体中获取
  if (!client_id) client_id = body.client_id;
  if (!client_secret) client_secret = body.client_secret;

  console.log('Received grant_type:', grant_type);
  console.log('Received code:', code);
  console.log('Received redirect_uri:', redirect_uri);
  console.log('Environment CLIENT_ID:', process.env.CLIENT_ID);
  console.log('Environment CLIENT_SECRET:', process.env.CLIENT_SECRET);
  console.log('Received client_id:', client_id);
  console.log('Received client_secret:', client_secret);
  console.log('Received code_verifier:', code_verifier);

  if (grant_type !== 'authorization_code') {
    console.log('Validation failed: Unsupported grant_type');
    return NextResponse.json({ error: 'Unsupported grant_type' }, { status: 400 });
  }

  if (client_id !== process.env.CLIENT_ID || client_secret !== process.env.CLIENT_SECRET) {
    console.log('Validation failed: Invalid client credentials');
    return NextResponse.json({ error: 'Invalid client credentials' }, { status: 400 });
  }

  if (redirect_uri !== 'https://shopify.com/authentication/63864635466/login/external/callback') {
    console.log('Validation failed: Invalid redirect_uri');
    return NextResponse.json({ error: 'Invalid redirect_uri' }, { status: 400 });
  }

  const secret = createSecretKey(process.env.JWT_SECRET || 'dGhpcy1pcy1hLXNlY3VyZS1zZWNyZXQtZm9yLWp3dC1zaWduaW5n', 'utf-8');
  let authData: AuthData;
  try {
    const { payload } = await jwtVerify(code, secret, { algorithms: ['HS256'] });
    authData = payload as AuthData;
    console.log('Decoded authData:', authData);
  } catch (error) {
    console.log('Validation failed: Invalid or expired code', error);
    return NextResponse.json({ error: 'Invalid or expired code' }, { status: 400 });
  }

  if (authData.code_challenge) {
    if (!code_verifier) {
      console.log('Validation failed: Missing code_verifier');
      return NextResponse.json({ error: 'Missing code_verifier' }, { status: 400 });
    }
    const verifierHash = createHash('sha256').update(code_verifier).digest('base64url');
    if (verifierHash !== authData.code_challenge) {
      console.log('Validation failed: Invalid code_verifier');
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