import { NextRequest, NextResponse } from 'next/server';

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const post_logout_redirect_uri = searchParams.get('post_logout_redirect_uri');
  const state = searchParams.get('state');

  if (!post_logout_redirect_uri) {
    return NextResponse.json({ error: 'invalid_request' }, { status: 400 });
  }

  // Validate post_logout_redirect_uri if needed
  if (!post_logout_redirect_uri.startsWith('https://shopify.com/')) {
    return NextResponse.json({ error: 'invalid_request' }, { status: 400 });
  }

  // Build redirect URL
  const redirectUrl = new URL(post_logout_redirect_uri);
  if (state) {
    redirectUrl.searchParams.set('state', state);
  }

  return NextResponse.redirect(redirectUrl);
} 