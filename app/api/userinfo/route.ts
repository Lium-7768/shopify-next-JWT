import { jwtVerify, importPKCS8 } from 'jose';
import { NextRequest, NextResponse } from 'next/server';
import { PRIVATE_KEY } from '@/app/constants/keys';

export async function GET(req: NextRequest) {
  try {
    const authHeader = req.headers.get('authorization');
    if (!authHeader?.startsWith('Bearer ')) {
      return NextResponse.json({ error: 'invalid_token' }, { status: 401 });
    }

    const token = authHeader.split(' ')[1];
    const privateKey = await importPKCS8(PRIVATE_KEY, 'RS256');

    try {
      const { payload } = await jwtVerify(token, privateKey, {
        algorithms: ['RS256'],
      });

      // Return user claims
      return NextResponse.json({
        sub: payload.sub,
        name: payload.name,
        given_name: payload.given_name,
        family_name: payload.family_name,
        email: payload.email,
        email_verified: payload.email_verified,
        locale: payload.locale,
        zoneinfo: payload.zoneinfo,
        phone_number: payload.phone_number,
        phone_number_verified: payload.phone_number_verified,
        address: payload.address
      });
    } catch (error) {
      console.error('Token verification failed:', error);
      return NextResponse.json({ error: 'invalid_token' }, { status: 401 });
    }
  } catch (error) {
    console.error('Error in userinfo endpoint:', error);
    return NextResponse.json({ error: 'server_error' }, { status: 500 });
  }
} 