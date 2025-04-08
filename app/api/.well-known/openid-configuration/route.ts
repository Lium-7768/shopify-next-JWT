import { NextRequest, NextResponse } from 'next/server';

export async function GET(req: NextRequest) {
  const config = {
    issuer: 'https://shopify-next-jwt.vercel.app',
    authorization_endpoint: 'https://shopify-next-jwt.vercel.app/api/authorize',
    token_endpoint: 'https://shopify-next-jwt.vercel.app/api/token',
    jwks_uri: 'https://shopify-next-jwt.vercel.app/api/jwks',
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['openid', 'email'],
    token_endpoint_auth_methods_supported: ['client_secret_post'],
    claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'email'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
  };
  return NextResponse.json(config);
}