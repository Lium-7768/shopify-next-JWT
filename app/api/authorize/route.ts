import { SignJWT, importPKCS8 } from 'jose';
import { NextRequest, NextResponse } from 'next/server';
import { PRIVATE_KEY } from '@/app/constants/keys';

interface ApiError extends Error {
  message: string;
  code?: string;
}

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const client_id = searchParams.get('client_id');
  const redirect_uri = searchParams.get('redirect_uri');
  const scope = searchParams.get('scope');
  const state = searchParams.get('state');
  const response_type = searchParams.get('response_type');
  const code_challenge = searchParams.get('code_challenge');
  const code_challenge_method = searchParams.get('code_challenge_method');

  console.log('GET /api/authorize - Request parameters:', {
    client_id,
    redirect_uri,
    scope,
    state,
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

  if (!redirect_uri?.startsWith('https://shopify.com/authentication/')) {
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

    if (!redirect_uri?.startsWith('https://shopify.com/authentication/')) {
      console.log('Invalid redirect_uri:', redirect_uri);
      return NextResponse.json({ error: 'invalid_request' }, { status: 400 });
    }

    if (code_challenge && code_challenge_method !== 'S256') {
      console.log('Invalid code_challenge_method:', code_challenge_method);
      return NextResponse.json({ error: 'invalid_request' }, { status: 400 });
    }

    console.log('Importing private key...');
    try {
      const privateKey = await importPKCS8(PRIVATE_KEY, 'RS256');
      console.log('Private key imported successfully');

      const code = await new SignJWT({
        user,
        code_challenge,
        scope: scope || 'openid email'
      })
        .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
        .setExpirationTime('10m')
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