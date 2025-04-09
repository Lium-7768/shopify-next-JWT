import { SignJWT, importPKCS8 } from 'jose';
import { NextRequest, NextResponse } from 'next/server';
import { PRIVATE_KEY } from '@/app/constants/keys';
import crypto from 'crypto';

interface ApiError extends Error {
  message: string;
  code?: string;
}

// 更新有效作用域数组，添加 customer-account-api 相关权限
const VALID_SCOPES = [
  'openid', 
  'profile', 
  'email', 
  'customer_read', 
  'customer_write',
  'customer-account-api:full',  // 添加Shopify账户API完全权限
  'customer-account-api:read',  // 添加Shopify账户API读取权限
  'customer-account-api:write'  // 添加Shopify账户API写入权限
];

// 验证重定向URI的函数，支持多种Shopify回调格式
function isValidRedirectUri(uri: string | null): boolean {
  if (!uri) return false;
  
  // 支持多种Shopify回调URL格式
  const validPatterns = [
    // 原来的格式
    /^https:\/\/shopify\.com\/authentication\/\d+\/login\/external\/callback/,
    // 新的格式
    /^https:\/\/shopify\.com\/\d+\/account\/callback/,
    // 另一个可能的格式(带source参数)
    /^https:\/\/shopify\.com\/\d+\/account\/callback\?source=core/
  ];
  
  return validPatterns.some(pattern => pattern.test(uri));
}

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
  // 添加对Shopify特有参数的支持
  const acr_values = searchParams.get('acr_values');
  const locale = searchParams.get('locale');

  console.log('GET /api/authorize - Request parameters:', {
    client_id,
    redirect_uri,
    scope,
    state,
    nonce,
    response_type,
    code_challenge,
    code_challenge_method,
    acr_values,
    locale
  });

  if (response_type !== 'code') {
    console.log('Invalid response_type:', response_type);
    return NextResponse.json({ error: 'unsupported_response_type' }, { status: 400 });
  }

  if (client_id !== process.env.CLIENT_ID) {
    console.log('Invalid client_id:', client_id);
    return NextResponse.json({ error: 'unauthorized_client' }, { status: 401 });
  }

  if (!isValidRedirectUri(redirect_uri)) {
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
  // 传递Shopify特有参数
  if (acr_values) {
    redirectUrl.searchParams.set('acr_values', acr_values);
  }
  if (locale) {
    redirectUrl.searchParams.set('locale', locale);
  }
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
      acr_values,  // 添加Shopify特有参数
      locale,      // 添加Shopify特有参数
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

    if (!isValidRedirectUri(redirect_uri)) {
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

      // 生成JWT代码
      const jwtCode = await new SignJWT({
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
        acr_values, // 包含认证上下文引用值
        locale,     // 包含语言区域设置
        user: {
          id: user.id,
          email: user.email,
          email_verified: true,
          name: user.name || user.email.split('@')[0],
          given_name: user.given_name || '',
          family_name: user.family_name || '',
          locale: locale || user.locale || 'en'
        }
      })
        .setProtectedHeader({ alg: 'RS256', typ: 'at+jwt', kid: '1' })
        .setJti(crypto.randomUUID())
        .setIssuedAt()
        .setExpirationTime(now + 600)
        .sign(privateKey);

      console.log('JWT code generated successfully');

      // 生成符合Shopify格式的代码 (可选，取决于Shopify期望的格式)
      // 如果你想完全模拟Shopify的代码格式，可以这样做:
      const shopifyStyleCode = `shcac_${Buffer.from(jwtCode).toString('base64').replace(/=/g, '')}`;
      
      // 默认使用JWT格式，如果需要完全匹配Shopify格式，可以改用shopifyStyleCode
      const codeToUse = jwtCode; // 或 shopifyStyleCode
      
      const redirectUrl = new URL(redirect_uri);
      
      // 添加source=core参数（如果是新格式的回调URL且尚未有source参数）
      if (redirect_uri.includes('/account/callback') && !redirect_uri.includes('source=')) {
        redirectUrl.searchParams.set('source', 'core');
      }
      
      redirectUrl.searchParams.set('code', codeToUse);
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