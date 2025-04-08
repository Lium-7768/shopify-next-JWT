import { NextResponse } from 'next/server';
import { importPKCS8, exportJWK } from 'jose';

export async function GET() {
  try {
    if (!process.env.PRIVATE_KEY) {
      console.error('PRIVATE_KEY is not set in environment variables');
      return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
    }

    // 导入私钥
    const privateKey = await importPKCS8(process.env.PRIVATE_KEY, 'RS256');

    // 提取公钥并转换为 JWK 格式
    const publicKeyJwk = await exportJWK(privateKey);
    publicKeyJwk.kid = '1'; // 设置一个唯一的 key ID
    publicKeyJwk.use = 'sig'; // 表示用于签名
    publicKeyJwk.alg = 'RS256'; // 算法

    // 返回 JWKS 格式
    return NextResponse.json({
      keys: [publicKeyJwk],
    });
  } catch (error) {
    console.error('Error generating JWKS:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}