import { NextRequest, NextResponse } from 'next/server';

export async function GET(req: NextRequest) {
  const jwks = {
    keys: [
      {
        kty: 'oct',
        kid: '1',
        use: 'sig',
        alg: 'HS256',
      },
    ],
  };
  return NextResponse.json(jwks);
}