export default function handler(req, res) {
  const config = {
    issuer: 'https://shopify-next-jwt.vercel.app',
    authorization_endpoint: 'https://shopify-next-jwt.vercel.app/api/authorize',
    token_endpoint: 'https://shopify-next-jwt.vercel.app/api/token',
    jwks_uri: 'https://shopify-next-jwt.vercel.app/api/.well-known/jwks.json',
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    token_endpoint_auth_methods_supported: ['client_secret_post'],
    code_challenge_methods_supported: ['S256'],
    scopes_supported: ['openid', 'email'],
    id_token_signing_alg_values_supported: ['HS256'],
  };
  res.status(200).json(config);
}