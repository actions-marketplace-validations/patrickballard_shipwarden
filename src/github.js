const API = process.env.GITHUB_API_URL || 'https://api.github.com';

async function request(token, method, url, body) {
  const res = await fetch(url.startsWith('http') ? url : `${API}${url}`, {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      accept: 'application/vnd.github+json',
      'x-github-api-version': '2022-11-28',
      'user-agent': 'shipwarden',
      ...(body ? { 'content-type': 'application/json' } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    const error = new Error(`GitHub API ${method} ${url} returned ${res.status}: ${text.slice(0, 200)}`);
    error.status = res.status;
    throw error;
  }
  return { data: res.status === 204 ? null : await res.json(), link: res.headers.get('link') };
}

async function paginate(token, url) {
  const items = [];
  for (let next = url; next; ) {
    const { data, link } = await request(token, 'GET', next);
    items.push(...data);
    next = link?.match(/<([^>]+)>;\s*rel="next"/)?.[1];
  }
  return items;
}

/** Paths added or modified by the pull request. */
export async function listPullFiles({ token, owner, repo, number }) {
  const files = await paginate(token, `/repos/${owner}/${repo}/pulls/${number}/files?per_page=100`);
  return new Set(files.filter((f) => f.status !== 'removed').map((f) => f.filename));
}

/** Edit our previous comment in place instead of posting a new one on every push. */
export async function upsertComment({ token, owner, repo, number, marker, body, createIfMissing }) {
  const comments = await paginate(token, `/repos/${owner}/${repo}/issues/${number}/comments?per_page=100`);
  const existing = comments.find((c) => c.body?.includes(marker));
  if (existing) {
    if (existing.body === body) return 'unchanged';
    await request(token, 'PATCH', `/repos/${owner}/${repo}/issues/comments/${existing.id}`, { body });
    return 'updated';
  }
  if (!createIfMissing) return 'skipped';
  await request(token, 'POST', `/repos/${owner}/${repo}/issues/${number}/comments`, { body });
  return 'created';
}
