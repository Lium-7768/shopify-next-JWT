import { useRouter } from 'next/router';
import { useState } from 'react';

export default function Login() {
  const router = useRouter();
  const { client_id, redirect_uri, scope, state, response_type, code_challenge, code_challenge_method } = router.query;

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    // 模拟验证用户（实际中应调用后端验证）
    if (email === 'user@example.com' && password === 'password123') {
      const res = await fetch('/api/authorize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_id,
          redirect_uri,
          scope,
          state,
          response_type,
          code_challenge,
          code_challenge_method,
          user: { id: 'user123', email },
        }),
      });
      if (res.ok) {
        const { redirectUrl } = await res.json();
        window.location.href = redirectUrl;
      }
    } else {
      alert('Invalid credentials');
    }
  };

  return (
    <div>
      <h1>Login</h1>
      <form onSubmit={handleSubmit}>
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="Email"
          required
        />
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Password"
          required
        />
        <button type="submit">Login</button>
      </form>
    </div>
  );
}