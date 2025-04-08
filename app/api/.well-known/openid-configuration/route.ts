import { NextRequest, NextResponse } from 'next/server';

export async function GET(req: NextRequest) {
  const config = {
    issuer: 'https://shopify-next-jwt.vercel.app',
    authorization_endpoint: 'https://shopify-next-jwt.vercel.app/api/authorize',
    token_endpoint: 'https://shopify-next-jwt.vercel.app/api/token',
    jwks_uri: 'https://shopify-next-jwt.vercel.app/api/.well-known/jwks.json',
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['client_secret_post'],
    code_challenge_methods_supported: ['S256'],
    scopes_supported: ['openid', 'email', 'https://shopify-next-jwt.vercel.app/'],
    id_token_signing_alg_values_supported: ['HS256'],
  };
  return NextResponse.json(config);
}