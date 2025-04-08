import { randomUUID } from 'crypto';
import { NextRequest, NextResponse } from 'next/server';
import redis from '../../../lib/redis';

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const client_id = searchParams.get('client_id');
  const redirect_uri = searchParams.get('redirect_uri');
  const scope = searchParams.get('scope') || '';
  const state = searchParams.get('state');
  const response_type = searchParams.get('response_type');
  const code_challenge = searchParams.get('code_challenge');
  const code_challenge_method = searchParams.get('code_challenge_method');

  // 验证 client_id 和 redirect_uri
  if (client_id !== process.env.CLIENT_ID || !redirect_uri?.startsWith('https://your-shopify-store.myshopify.com')) {
    return NextResponse.json({ error: 'Invalid client_id or redirect_uri' }, { status: 400 });
  }

  // 验证 response_type 为 "code"
  if (response_type !== 'code') {
    return NextResponse.json({ error: 'Unsupported response_type' }, { status: 400 });
  }

  // 验证 scope 包含 openid 和 email
  if (!scope.includes('openid') || !scope.includes('email')) {
    return NextResponse.json({ error: 'Invalid scope' }, { status: 400 });
  }

  // 如果使用 PKCE，验证 code_challenge_method
  if (code_challenge && code_challenge_method !== 'S256') {
    return NextResponse.json({ error: 'Unsupported code_challenge_method' }, { status: 400 });
  }

  // 跳转到登录页面
  const loginUrl = `/login?${searchParams.toString()}`;
  return NextResponse.redirect(new URL(loginUrl, req.url));
}

export async function POST(req: NextRequest) {
  const { client_id, redirect_uri, scope, state, response_type, code_challenge, code_challenge_method, user } = await req.json();

  // 验证 client_id 和 redirect_uri
  if (client_id !== process.env.CLIENT_ID || !redirect_uri?.startsWith('https://your-shopify-store.myshopify.com')) {
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

  const code = randomUUID();
  await redis.setEx(code, 600, JSON.stringify({ user, code_challenge })); // 10 分钟过期

  const redirectUrl = `${redirect_uri}?code=${code}&state=${state}`;
  return NextResponse.json({ redirectUrl });
}