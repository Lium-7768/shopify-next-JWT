import { SignJWT, jwtVerify, importPKCS8 } from 'jose';
import { createHash, createPublicKey } from 'crypto';
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

    const { grant_type, code, redirect_uri, code_verifier, refresh_token } = body;

    // 如果没有从 Basic Auth 获取 client_id 和 client_secret，则尝试从请求体中获取
    if (!client_id) client_id = body.client_id;
    if (!client_secret) client_secret = body.client_secret;

    console.log('Processing token request:', {
      grant_type,
      redirect_uri,
      client_id,
      code_verifier: code_verifier ? '[PRESENT]' : '[NOT PRESENT]',
      refresh_token: refresh_token ? '[PRESENT]' : '[NOT PRESENT]'
    });

    if (grant_type !== 'authorization_code' && grant_type !== 'refresh_token') {
      console.log('Invalid grant_type:', grant_type);
      return NextResponse.json({ error: 'unsupported_grant_type' }, { status: 400 });
    }

    if (client_id !== process.env.CLIENT_ID || client_secret !== process.env.CLIENT_SECRET) {
      console.log('Invalid client credentials');
      return NextResponse.json({ error: 'invalid_client' }, { status: 401 });
    }

    // 对于授权码类型，验证重定向 URI
    if (grant_type === 'authorization_code') {
      // 创建有效的重定向URI模式列表
      const validRedirectPatterns = [
        // 原来的格式
        /^https:\/\/shopify\.com\/authentication\/\d+\/login\/external\/callback/,
        // 新的格式 - 官方文档中的格式
        /^https:\/\/shopify\.com\/\d+\/account\/callback/,
        // 带source参数的格式(官方示例中使用)
        /^https:\/\/shopify\.com\/\d+\/account\/callback\?source=core/
      ];
      
      // 检查重定向URI是否匹配任何有效模式
      const isValidRedirectUri = validRedirectPatterns.some(pattern => pattern.test(redirect_uri));
      
      if (!isValidRedirectUri) {
        console.log('Invalid redirect_uri:', redirect_uri);
        return NextResponse.json({ error: 'invalid_request' }, { status: 400 });
      }
    }

    console.log('Importing keys...');
    try {
      // 从私钥创建公钥
      const publicKey = createPublicKey({
        key: PRIVATE_KEY,
        format: 'pem',
      });

      // 导入私钥用于签名
      const privateKey = await importPKCS8(PRIVATE_KEY, 'RS256');

      console.log('Keys imported successfully');

      const now = Math.floor(Date.now() / 1000);
      const accessTokenExpiresIn = 3600; // 1 hour
      const refreshTokenExpiresIn = 30 * 24 * 3600; // 30 days
      const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || 'https://shopify-next-jwt.vercel.app';

      // 处理 authorization_code 授权类型
      if (grant_type === 'authorization_code') {
        let authData: AuthData;
        try {
          // 使用公钥验证 code
          const { payload } = await jwtVerify(code, publicKey, {
            algorithms: ['RS256'],
            clockTolerance: 60,  // Allow 1 minute clock skew
            issuer: baseUrl,
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

        console.log('Generating tokens...');

        // 生成 access_token
        const accessToken = await new SignJWT({
          iss: baseUrl,
          sub: authData.sub,
          aud: client_id,
          jti: crypto.randomUUID(),
          scope: authData.scope,
        })
          .setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: 'idp-key-2025-04-10' })
          .setIssuedAt()
          .setExpirationTime(now + accessTokenExpiresIn)
          .sign(privateKey);

        // 生成 refresh_token
        const refreshToken = await new SignJWT({
          iss: baseUrl,
          sub: authData.sub,
          aud: client_id,
          jti: crypto.randomUUID(),
          scope: authData.scope,
          user: authData.user, // 在 refresh token 中包含用户信息，以便刷新时使用
        })
          .setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: 'idp-key-2025-04-10' })
          .setIssuedAt()
          .setExpirationTime(now + refreshTokenExpiresIn)
          .sign(privateKey);

        // 生成 id_token
        const idToken = await new SignJWT({
          iss: baseUrl,
          sub: authData.sub,
          aud: client_id,
          exp: now + accessTokenExpiresIn,
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
          .setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: 'idp-key-2025-04-10' })
          .sign(privateKey);

        console.log('Tokens generated successfully');

        console.log('accessToken:', {
          access_token: accessToken,
          token_type: 'Bearer',
          expires_in: accessTokenExpiresIn,
          refresh_token: refreshToken,
          id_token: idToken,
          scope: authData.scope
        });

        // 返回所有令牌
        return new NextResponse(
          JSON.stringify({
            access_token: accessToken,
            token_type: 'Bearer',
            expires_in: accessTokenExpiresIn,
            refresh_token: refreshToken,
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
      } 
      // 处理 refresh_token 授权类型
      else if (grant_type === 'refresh_token') {
        if (!refresh_token) {
          console.log('Missing refresh_token');
          return NextResponse.json({ error: 'invalid_request' }, { status: 400 });
        }

        let refreshTokenData: any;
        try {
          // 验证 refresh_token
          const { payload } = await jwtVerify(refresh_token, publicKey, {
            algorithms: ['RS256'],
            clockTolerance: 60,  // Allow 1 minute clock skew
            issuer: baseUrl,
            audience: client_id,
          });
          refreshTokenData = payload;
          console.log('Refresh token verification successful');
        } catch (error: unknown) {
          const apiError = error as ApiError;
          console.error('Refresh token verification failed:', apiError);
          return NextResponse.json({ error: 'invalid_grant' }, { status: 400 });
        }

        // 生成新的访问令牌
        const newAccessToken = await new SignJWT({
          iss: baseUrl,
          sub: refreshTokenData.sub,
          aud: client_id,
          jti: crypto.randomUUID(),
          scope: refreshTokenData.scope,
        })
          .setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: 'idp-key-2025-04-10' })
          .setIssuedAt()
          .setExpirationTime(now + accessTokenExpiresIn)
          .sign(privateKey);

        // 生成新的刷新令牌（可选）
        const newRefreshToken = await new SignJWT({
          iss: baseUrl,
          sub: refreshTokenData.sub,
          aud: client_id,
          jti: crypto.randomUUID(),
          scope: refreshTokenData.scope,
          user: refreshTokenData.user,
        })
          .setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: 'idp-key-2025-04-10' })
          .setIssuedAt()
          .setExpirationTime(now + refreshTokenExpiresIn)
          .sign(privateKey);

        console.log('New tokens generated successfully');

        // 返回新的访问令牌和刷新令牌
        return new NextResponse(
          JSON.stringify({
            access_token: newAccessToken,
            token_type: 'Bearer',
            expires_in: accessTokenExpiresIn,
            refresh_token: newRefreshToken,
            scope: refreshTokenData.scope
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
      }
    } catch (error: unknown) {
      const apiError = error as ApiError;
      console.error('Error processing keys:', apiError);
      return NextResponse.json({ error: 'server_error', details: apiError.message }, { status: 500 });
    }
  } catch (error: unknown) {
    const apiError = error as ApiError;
    console.error('Unexpected error in /api/token:', apiError);
    return NextResponse.json({ error: 'server_error' }, { status: 500 });
  }
}