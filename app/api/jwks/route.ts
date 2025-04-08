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
    };

    // Return JWKS
    return NextResponse.json({
      keys: [completeJwk]
    });
  } catch (error) {
    console.error('Error generating JWKS:', error);
    return NextResponse.json({ error: 'server_error' }, { status: 500 });
  }
}