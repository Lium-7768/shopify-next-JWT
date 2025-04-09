import { createPublicKey } from 'crypto';
import { NextRequest, NextResponse } from 'next/server';
import { PRIVATE_KEY } from '../../constants/keys';

/**
 * JWKS 端点实现 - 符合 RFC 7517 规范
 * 参考: https://datatracker.ietf.org/doc/html/rfc7517#section-5
 */
export async function GET(req: NextRequest) {
  console.log('--------------- get jwks ---------------');
  try {
    // 从私钥创建公钥
    const publicKey = createPublicKey({
      key: PRIVATE_KEY,
      format: 'pem',
    });

    // 导出公钥组件为 JWK 格式
    const jwk = publicKey.export({ format: 'jwk' });

    // 添加 RFC 7517 要求的 JWK 参数
    const completeJwk = {
      ...jwk,
      // 必需参数
      kty: 'RSA',                // 密钥类型 (必需) - 4.1 节
      
      // 建议的 RSA 参数已由 publicKey.export() 提供:
      // n: modulus (Base64urlUInt-encoded) - 在 jwk 中已存在
      // e: exponent (Base64urlUInt-encoded) - 在 jwk 中已存在

      // 推荐参数
      use: 'sig',                // 公钥用途: 签名 - 4.2 节
      alg: 'RS256',              // 签名算法 - 4.4 节 
      kid: '1',                  // 密钥 ID - 4.5 节

      // RFC 7517 4.7 节中的额外可选标准参数
      x5c: [],                   // X.509 证书链 (可选)
      x5t: null,                 // X.509 证书 SHA-1 指纹 (可选)
      'x5t#S256': null,          // X.509 证书 SHA-256 指纹 (可选)
    };

    // 删除空值字段
    for (const [key, value] of Object.entries(completeJwk)) {
      if (value === null || value === undefined || (Array.isArray(value) && value.length === 0)) {
        delete completeJwk[key];
      }
    }

    // 确保所有 RSA 必需参数存在
    if (!completeJwk.n || !completeJwk.e) {
      throw new Error('缺少必需的 RSA 参数 (n 和 e)');
    }

    console.log('completeJwk:', completeJwk);

    // 返回 JWKS（一个包含 keys 数组的 JSON 对象），根据 RFC 7517 第 5 节
    return new NextResponse(
      JSON.stringify({
        keys: [completeJwk]
      }),
      {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Cache-Control': 'public, max-age=86400',  // 缓存 24 小时
          'Expires': new Date(Date.now() + 86400000).toUTCString()  // 从现在起 24 小时后
        }
      }
    );
  } catch (error) {
    console.error('生成 JWKS 时出错:', error);
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