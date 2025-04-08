import { SignJWT, jwtVerify, importPKCS8 } from 'jose';
import { createHash } from 'crypto';
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
  try {
    let body: any;
    let client_id: string | undefined;
    let client_secret: string | undefined;

    // 解析 Authorization 头部（Basic Auth）
    const authHeader = req.headers.get('authorization');
    if (authHeader && authHeader.startsWith('Basic ')) {
      const base64Credentials = authHeader.split(' ')[1];
      const credentials = Buffer.from(base64Credentials, 'base64').toString('utf-8');
      const [id, secret] = credentials.split(':');
      client_id = id;
      client_secret = secret;
    }

    const contentType = req.headers.get('content-type') || '';

    // 解析请求体
    if (contentType.includes('application/json')) {
      body = await req.json();
    } else if (contentType.includes('application/x-www-form-urlencoded')) {
      const formData = await req.formData();
      body = Object.fromEntries(formData);
    } else {
      return NextResponse.json({ error: 'unsupported_content_type' }, { status: 400 });
    }

    const { grant_type, code, redirect_uri, code_verifier } = body;

    // 如果没有从 Basic Auth 获取 client_id 和 client_secret，则尝试从请求体中获取
    if (!client_id) client_id = body.client_id;
    if (!client_secret) client_secret = body.client_secret;

    if (grant_type !== 'authorization_code') {
      return NextResponse.json({ error: 'unsupported_grant_type' }, { status: 400 });
    }

    if (client_id !== process.env.CLIENT_ID || client_secret !== process.env.CLIENT_SECRET) {
      return NextResponse.json({ error: 'invalid_client' }, { status: 401 });
    }

    if (!redirect_uri.startsWith('https://shopify.com/authentication/')) {
      return NextResponse.json({ error: 'invalid_request' }, { status: 400 });
    }

    if (!process.env.PRIVATE_KEY) {
      console.error('PRIVATE_KEY is not set in environment variables');
      return NextResponse.json({ error: 'server_error' }, { status: 500 });
    }

    // 导入私钥
    const privateKey = await importPKCS8(process.env.PRIVATE_KEY, 'RS256');

    let authData: AuthData;
    try {
      const { payload } = await jwtVerify(code, privateKey, {
        algorithms: ['RS256'],
        clockTolerance: 0,
      });
      authData = payload as AuthData;
    } catch (error) {
      return NextResponse.json({ error: 'invalid_grant' }, { status: 400 });
    }

    // 如果 code_challenge 存在，则必须验证 code_verifier
    if (authData.code_challenge) {
      if (!code_verifier) {
        return NextResponse.json({ error: 'invalid_request' }, { status: 400 });
      }
      const verifierHash = createHash('sha256').update(code_verifier).digest('base64url');
      if (verifierHash !== authData.code_challenge) {
        return NextResponse.json({ error: 'invalid_grant' }, { status: 400 });
      }
    }

    const now = Math.floor(Date.now() / 1000);
    const expiresIn = 3600; // 1 hour

    // 生成 access_token
    const accessToken = await new SignJWT({
      sub: authData.user.id,
      scope: 'openid email',
    })
      .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
      .setIssuedAt()
      .setExpirationTime(now + expiresIn)
      .sign(privateKey);

    // 生成 id_token
    const idToken = await new SignJWT({
      sub: authData.user.id,
      email: authData.user.email,
      iss: 'https://shopify-next-jwt.vercel.app',
      aud: client_id,
      iat: now,
      exp: now + expiresIn,
    })
      .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
      .sign(privateKey);

    // 生成 refresh_token
    const refreshToken = await new SignJWT({
      sub: authData.user.id,
      type: 'refresh',
    })
      .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
      .setIssuedAt()
      .setExpirationTime('30d') // 30天有效期
      .sign(privateKey);

    return NextResponse.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: expiresIn,
      refresh_token: refreshToken,
      id_token: idToken,
      scope: 'openid email',
    });
  } catch (error) {
    console.error('Unexpected error in /api/token:', error);
    return NextResponse.json({ error: 'server_error' }, { status: 500 });
  }
}