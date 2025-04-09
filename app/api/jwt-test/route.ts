import { SignJWT, jwtVerify, importPKCS8 } from 'jose';
import { createHash, createPublicKey } from 'crypto';
import { NextRequest, NextResponse } from 'next/server';
import { PRIVATE_KEY } from '@/app/constants/keys';

// 示例数据
const testData = {
  "client_id": "12345678",
  "redirect_uri": "https://shopify.com/authentication/63864635466/login/external/callback",
  "scope": "openid email",
  "state": "01JRCCFS544HDT1WBHJHXKVP8Q",
  "response_type": "code",
  "code_challenge": null,
  "code_challenge_method": null,
  "user": {
    "id": "user123",
    "email": "user@example.com"
  }
};

export async function GET(req: NextRequest) {
  try {
    // 从私钥创建公钥
    const publicKey = createPublicKey({
      key: PRIVATE_KEY,
      format: 'pem',
    });
    
    // 导入私钥用于签名
    const privateKey = await importPKCS8(PRIVATE_KEY, 'RS256');
    
    // 使用私钥签名JWT
    const now = Math.floor(Date.now() / 1000);
    const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || 'https://shopify-next-jwt.vercel.app';
    
    const token = await new SignJWT(testData)
      .setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: '1' })
      .setIssuedAt()
      .setExpirationTime(now + 3600) // 1小时后过期
      .setIssuer(baseUrl)
      .setAudience('12345678')
      .sign(privateKey);
    
    // 解析JWT头部（不需要密钥）
    const parts = token.split('.');
    const headerBase64 = parts[0];
    const header = JSON.parse(Buffer.from(headerBase64, 'base64').toString());
    
    // 使用公钥验证JWT
    const { payload: decodedPayload } = await jwtVerify(token, publicKey, {
      algorithms: ['RS256'],
      issuer: baseUrl,
      audience: '12345678',
    });
    
    // 返回结果
    return NextResponse.json({
      originalData: testData,
      jwt: token,
      header: header,
      decodedData: decodedPayload
    }, { status: 200 });
  } catch (error: any) {
    console.error("JWT测试错误:", error);
    return NextResponse.json({ error: "JWT处理失败", details: error.message }, { status: 500 });
  }
} 