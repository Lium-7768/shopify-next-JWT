import { Suspense } from 'react';
import Login from './Login';

// 父组件，使用 Suspense 包裹 Login
export default function LoginPage() {
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <Login />
    </Suspense>
  );
}