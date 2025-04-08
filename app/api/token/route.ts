import { SignJWT, jwtVerify, importPKCS8 } from 'jose';
import { createHash } from 'crypto';
import { NextRequest, NextResponse } from 'next/server';
import { PRIVATE_KEY } from '@/app/constants/keys';
import crypto from 'crypto';

interface ApiError extends Error {
  message: string;
  code?: string;
}

interface AuthData {
  user: {
    id: string;
    email: string;
    name?: string;
    given_name?: string;
    family_name?: string;
    locale?: string;
  };
  code_challenge?: string;
  exp: number;
  nonce: string;
  [key: string]: any;
}

export async function POST(req: NextRequest) {
  try {
    let body: any;
    let client_id: string | undefined;
    let client_secret: string | undefined;

    // 解析 Authorization 头部（Basic Auth）
    const authHeader = req.headers.get('authorization');
    console.log('Authorization header:', authHeader);

    if (authHeader && authHeader.startsWith('Basic ')) {
      const base64Credentials = authHeader.split(' ')[1];
      const credentials = Buffer.from(base64Credentials, 'base64').toString('utf-8');
      const [id, secret] = credentials.split(':');
      client_id = id;
      client_secret = secret;
      console.log('Credentials from Basic Auth:', { client_id });
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
      console.log('Unsupported content type:', contentType);
      return NextResponse.json({ error: 'unsupported_content_type' }, { status: 400 });
    }

    console.log('Request body:', body);

    const { grant_type, code, redirect_uri, code_verifier } = body;

    // 如果没有从 Basic Auth 获取 client_id 和 client_secret，则尝试从请求体中获取
    if (!client_id) client_id = body.client_id;
    if (!client_secret) client_secret = body.client_secret;

    console.log('Processing token request:', {
      grant_type,
      redirect_uri,
      client_id,
      code_verifier: code_verifier ? '[PRESENT]' : '[NOT PRESENT]'
    });

    if (grant_type !== 'authorization_code') {
      console.log('Invalid grant_type:', grant_type);
      return NextResponse.json({ error: 'unsupported_grant_type' }, { status: 400 });
    }

    if (client_id !== process.env.CLIENT_ID || client_secret !== process.env.CLIENT_SECRET) {
      console.log('Invalid client credentials');
      return NextResponse.json({ error: 'invalid_client' }, { status: 401 });
    }

    if (!redirect_uri.startsWith('https://shopify.com/authentication/') || !redirect_uri.includes('/login/external/callback')) {
      console.log('Invalid redirect_uri:', redirect_uri);
      return NextResponse.json({ error: 'invalid_request' }, { status: 400 });
    }

    console.log('Importing private key...');
    try {
      const privateKey = await importPKCS8(PRIVATE_KEY, 'RS256');
      console.log('Private key imported successfully');

      let authData: AuthData;
      try {
        const { payload } = await jwtVerify(code, privateKey, {
          algorithms: ['RS256'],
          clockTolerance: 60,  // Allow 1 minute clock skew
          issuer: process.env.NEXT_PUBLIC_BASE_URL || 'https://shopify-next-jwt.vercel.app',
          audience: client_id,
        });
        authData = payload as AuthData;
        console.log('Code verification successful');
      } catch (error: unknown) {
        const apiError = error as ApiError;
        console.error('Code verification failed:', apiError);
        return NextResponse.json({ error: 'invalid_grant' }, { status: 400 });
      }

      // 如果 code_challenge 存在，则必须验证 code_verifier
      if (authData.code_challenge) {
        if (!code_verifier) {
          console.log('Missing code_verifier');
          return NextResponse.json({ error: 'invalid_request' }, { status: 400 });
        }
        const verifierHash = createHash('sha256').update(code_verifier).digest('base64url');
        console.log('PKCE verification:', {
          expected: authData.code_challenge,
          actual: verifierHash
        });
        if (verifierHash !== authData.code_challenge) {
          console.log('Invalid code_verifier');
          return NextResponse.json({ error: 'invalid_grant' }, { status: 400 });
        }
        console.log('PKCE verification successful');
      }

      const now = Math.floor(Date.now() / 1000);
      const expiresIn = 3600; // 1 hour

      console.log('Generating tokens...');

      // 生成 access_token
      const accessToken = await new SignJWT({
        iss: process.env.NEXT_PUBLIC_BASE_URL || 'https://shopify-next-jwt.vercel.app',
        sub: authData.sub,
        aud: client_id,
        jti: crypto.randomUUID(),
        scope: authData.scope,
      })
        .setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: '1' })
        .setIssuedAt()
        .setExpirationTime(now + expiresIn)
        .sign(privateKey);

      // 生成 id_token
      const idToken = await new SignJWT({
        iss: process.env.NEXT_PUBLIC_BASE_URL || 'https://shopify-next-jwt.vercel.app',
        sub: authData.sub,
        aud: client_id,
        exp: now + expiresIn,
        iat: now,
        auth_time: authData.auth_time,
        nonce: authData.nonce,
        email: authData.user.email,
        email_verified: true,
        name: authData.user.name,
        given_name: authData.user.given_name,
        family_name: authData.user.family_name,
        locale: authData.user.locale,
        at_hash: createHash('sha256').update(accessToken).digest('base64url').substring(0, 32),
      })
        .setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: '1' })
        .sign(privateKey);

      console.log('Tokens generated successfully');

      // Return response with proper headers
      return new NextResponse(
        JSON.stringify({
          access_token: accessToken,
          token_type: 'Bearer',
          expires_in: expiresIn,
          id_token: idToken,
          scope: authData.scope
        }),
        {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store',
            'Pragma': 'no-cache'
          }
        }
      );
    } catch (error: unknown) {
      const apiError = error as ApiError;
      console.error('Error processing private key:', apiError);
      return NextResponse.json({ error: 'server_error', details: apiError.message }, { status: 500 });
    }
  } catch (error: unknown) {
    const apiError = error as ApiError;
    console.error('Unexpected error in /api/token:', apiError);
    return NextResponse.json({ error: 'server_error' }, { status: 500 });
  }
}