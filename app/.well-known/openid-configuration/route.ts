import { NextRequest, NextResponse } from 'next/server';

export async function GET(req: NextRequest) {
  const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || 'https://shopify-next-jwt.vercel.app';

  const config = {
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/api/authorize`,
    token_endpoint: `${baseUrl}/api/token`,
    jwks_uri: `${baseUrl}/.well-known/jwks.jsn`,
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported: [
      'openid',
      'email',
      // 'profile',
      // 'customer_read',
      // 'customer_write'
    ],
    claims_supported: [
      'sub',
      'iss',
      'aud',
      'exp',
      'iat',
      'auth_time',
      'nonce',
      'name',
      'given_name',
      'family_name',
      'email',
      'email_verified',
      'locale',
      'zoneinfo',
      'address'
    ],
    token_endpoint_auth_methods_supported: ['client_secret_basic'],
    grant_types_supported: ['authorization_code'],
    code_challenge_methods_supported: ['S256'],
    userinfo_endpoint: `${baseUrl}/api/userinfo`,
    end_session_endpoint: `${baseUrl}/api/logout`,
    request_parameter_supported: false,
    request_uri_parameter_supported: false,
    require_request_uri_registration: false,
    claims_parameter_supported: false,
    revocation_endpoint: `${baseUrl}/api/token/revoke`,
    backchannel_logout_supported: false,
    backchannel_logout_session_supported: false,
    frontchannel_logout_supported: false,
    frontchannel_logout_session_supported: false
  };

  return new NextResponse(
    JSON.stringify(config),
    {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Cache-Control': 'public, max-age=86400',  // Cache for 24 hours
        'Expires': new Date(Date.now() + 86400000).toUTCString()  // 24 hours from now
      }
    }
  );
}