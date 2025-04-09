import { NextRequest, NextResponse } from 'next/server';

/**
 * OpenID Provider 元数据端点
 * 符合 OpenID Connect Discovery 1.0 规范
 * 参考: https://openid.net/specs/openid-connect-discovery-1_0.html
 */
export async function GET(req: NextRequest) {
  const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || 'https://shopify-next-jwt.vercel.app';

  // OpenID Provider Metadata - 3.1 节
  const config = {
    // 必需参数
    issuer: baseUrl,                                                  // 3.2 节
    authorization_endpoint: `${baseUrl}/api/authorize`,               // 3.3 节
    token_endpoint: `${baseUrl}/api/token`,                           // 3.4 节
    jwks_uri: `${baseUrl}/.well-known/jwks.jsn`,                      // 3.5 节
    response_types_supported: ['code'],                               // 3.6 节
    subject_types_supported: ['public'],                              // 3.7 节
    id_token_signing_alg_values_supported: ['RS256'],                 // 3.8 节

    // 推荐参数
    userinfo_endpoint: `${baseUrl}/api/userinfo`,                     // 3.9 节
    registration_endpoint: null,                                       // 3.14 节, 暂不支持动态注册
    scopes_supported: [                                               // 3.10 节
      'openid',
      'email',
      // 'profile',
      // 'customer_read',
      // 'customer_write'
    ],
    claims_supported: [                                               // 3.11 节
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

    // 可选参数
    token_endpoint_auth_methods_supported: [                          // 3.12 节
      'client_secret_basic',
      'client_secret_post'
    ],
    token_endpoint_auth_signing_alg_values_supported: ['RS256'],      // 3.13 节
    service_documentation: null,                                       // 3.15 节, 未提供服务文档
    ui_locales_supported: ['en-US', 'zh-CN'],                          // 3.16 节
    op_policy_uri: null,                                               // 3.17 节, 未提供隐私政策
    op_tos_uri: null,                                                  // 3.18 节, 未提供服务条款

    // 额外的可选参数
    revocation_endpoint: `${baseUrl}/api/token/revoke`,               // 2.3 节 OAuth 2.0 Token Revocation
    end_session_endpoint: `${baseUrl}/api/logout`,                    // OpenID Connect Session Management 1.0
    grant_types_supported: ['authorization_code', 'refresh_token'],   // 扩展授权类型
    code_challenge_methods_supported: ['S256'],                       // PKCE 支持
    response_modes_supported: ['query', 'fragment'],                   // 响应模式
    display_values_supported: ['page'],                                // 显示模式
    claim_types_supported: ['normal'],                                 // 声明类型
    request_parameter_supported: false,                               // JWT-secured 授权请求
    request_uri_parameter_supported: false,                           // JWT-secured 授权请求 URI
    require_request_uri_registration: false,                          // 是否要求注册请求 URI
    claims_parameter_supported: false,                                // 声明请求参数
    backchannel_logout_supported: false,                              // 后端通道登出
    backchannel_logout_session_supported: false,                      // 后端通道登出会话
    frontchannel_logout_supported: false,                             // 前端通道登出
    frontchannel_logout_session_supported: false,                     // 前端通道登出会话
    prompt_values_supported: ['none', 'login', 'consent'],             // 支持的提示值
  };

  // 删除空值字段
  for (const [key, value] of Object.entries(config)) {
    if (value === null || value === undefined || (Array.isArray(value) && value.length === 0)) {
      delete config[key];
    }
  }

  return new NextResponse(
    JSON.stringify(config),
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
}