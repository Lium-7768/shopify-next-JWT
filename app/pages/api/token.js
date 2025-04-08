import { SignJWT } from 'jose';
import { createSecretKey, createHash } from 'crypto';
import redis from '../../lib/redis';

export default async function handler(req, res) {
  const { grant_type, code, redirect_uri, client_id, client_secret, code_verifier } = req.body;

  if (grant_type !== 'authorization_code') {
    return res.status(400).json({ error: 'Unsupported grant_type' });
  }

  if (client_id !== process.env.CLIENT_ID || client_secret !== process.env.CLIENT_SECRET) {
    return res.status(400).json({ error: 'Invalid client credentials' });
  }

  const authDataString = await redis.get(code);
  if (!authDataString) {
    return res.status(400).json({ error: 'Invalid code' });
  }
  const authData = JSON.parse(authDataString);

  if (authData.code_challenge) {
    if (!code_verifier) {
      return res.status(400).json({ error: 'Missing code_verifier' });
    }
    const verifierHash = createHash('sha256').update(code_verifier).digest('base64url');
    if (verifierHash !== authData.code_challenge) {
      return res.status(400).json({ error: 'Invalid code_verifier' });
    }
  }

  const secret = createSecretKey(process.env.JWT_SECRET, 'utf-8');
  const accessToken = await new SignJWT({ sub: authData.user.id })
    .setProtectedHeader({ alg: 'HS256' })
    .setExpirationTime('1h')
    .sign(secret);

  const idToken = await new SignJWT({
    sub: authData.user.id,
    email: authData.user.email,
    iss: 'https://shopify-next-jwt.vercel.app',
    aud: client_id,
    exp: Math.floor(Date.now() / 1000) + 3600,
  })
    .setProtectedHeader({ alg: 'HS256' })
    .sign(secret);

  res.status(200).json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 3600,
    id_token: idToken,
  });

  await redis.del(code);
}