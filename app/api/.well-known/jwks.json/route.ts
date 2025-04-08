import { createPublicKey } from 'crypto';
import { NextRequest, NextResponse } from 'next/server';
import { PRIVATE_KEY } from '@/app/constants/keys';

export async function GET(req: NextRequest) {
  try {
    // Convert private key to public key
    const publicKey = createPublicKey({
      key: PRIVATE_KEY,
      format: 'pem',
    });

    // Export public key components in JWK format
    const jwk = publicKey.export({ format: 'jwk' });

    // Add required JWK parameters
    const completeJwk = {
      ...jwk,
      use: 'sig',
      alg: 'RS256',
      kid: '1', // Key ID
      kty: 'RSA',
    };

    // Ensure all required RSA JWK parameters are present
    if (!completeJwk.n || !completeJwk.e) {
      throw new Error('Missing required RSA parameters');
    }

    // Return JWKS with proper content type
    return new NextResponse(
      JSON.stringify({ keys: [completeJwk] }),
      {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Cache-Control': 'public, max-age=86400, s-maxage=86400'
        }
      }
    );
  } catch (error) {
    console.error('Error generating JWKS:', error);
    return NextResponse.json({ error: 'server_error' }, { status: 500 });
  }
}