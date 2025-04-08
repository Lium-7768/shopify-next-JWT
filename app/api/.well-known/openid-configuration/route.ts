import { NextRequest, NextResponse } from 'next/server';

export async function GET(req: NextRequest) {
  const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || 'https://shopify-next-jwt.vercel.app';

  const config = {
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/api/authorize`,
    token_endpoint: `${baseUrl}/api/token`,
    jwks_uri: `${baseUrl}/api/jwks`,
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['openid', 'profile', 'email', 'customer_read', 'customer_write'],
    claims_supported: [
      'sub',
      'iss',
      'aud',
      'exp',
      'iat',
      'name',
      'given_name',
      'family_name',
      'email',
      'email_verified',
      'locale',
      'zoneinfo',
      'phone_number',
      'phone_number_verified',
      'address'
    ],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    userinfo_endpoint: `${baseUrl}/api/userinfo`,
    end_session_endpoint: `${baseUrl}/api/logout`,
  };

  return NextResponse.json(config);
}