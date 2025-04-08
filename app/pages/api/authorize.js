import { randomUUID } from 'crypto';
import redis from '../../lib/redis';

export default async function handler(req, res) {
  const { client_id, redirect_uri, scope, state, response_type, code_challenge, code_challenge_method, user } = req.method === 'POST' ? req.body : req.query;

  if (!user) {
    const loginUrl = `/login?${new URLSearchParams(req.query).toString()}`;
    return res.redirect(302, loginUrl);
  }

  if (client_id !== process.env.CLIENT_ID || !redirect_uri.startsWith('https://your-shopify-store.myshopify.com')) {
    return res.status(400).json({ error: 'Invalid client_id or redirect_uri' });
  }

  if (response_type !== 'code') {
    return res.status(400).json({ error: 'Unsupported response_type' });
  }

  if (!scope.includes('openid') || !scope.includes('email')) {
    return res.status(400).json({ error: 'Invalid scope' });
  }

  if (code_challenge && code_challenge_method !== 'S256') {
    return res.status(400).json({ error: 'Unsupported code_challenge_method' });
  }

  const code = randomUUID();
  await redis.setEx(code, 600, JSON.stringify({ user, code_challenge })); // 10 分钟过期

  const redirectUrl = `${redirect_uri}?code=${code}&state=${state}`;
  if (req.method === 'POST') {
    return res.status(200).json({ redirectUrl });
  }
  res.redirect(302, redirectUrl);
}