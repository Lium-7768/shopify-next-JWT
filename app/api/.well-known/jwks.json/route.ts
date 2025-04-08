import { createPublicKey } from 'crypto';
import { NextRequest, NextResponse } from 'next/server';
import { PRIVATE_KEY } from '../../../constants/keys';

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
      use: 'sig',        // Key usage: signature
      alg: 'RS256',      // Algorithm used
      kid: '1',          // Key ID
      kty: 'RSA',        // Key type
    };

    // Ensure all required RSA JWK parameters are present
    if (!completeJwk.n || !completeJwk.e) {
      throw new Error('Missing required RSA parameters');
    }

    // Return JWKS with proper content type and caching headers
    return new NextResponse(
      JSON.stringify({
        keys: [completeJwk]
      }),
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
  } catch (error) {
    console.error('Error generating JWKS:', error);
    return new NextResponse(
      JSON.stringify({ error: 'server_error' }),
      {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store',
          'Pragma': 'no-cache'
        }
      }
    );
  }
}