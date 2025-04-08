export default function handler(req, res) {
  const jwks = {
    keys: [
      {
        kty: 'oct',
        kid: '1',
        use: 'sig',
        alg: 'HS256',
        // 不包含 k 字段，因为 HS256 是对称算法，密钥不公开
      },
    ],
  };
  res.status(200).json(jwks);
}