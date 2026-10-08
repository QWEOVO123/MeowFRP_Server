// Setup uses the browser's origin, not its current route/query/hash and not
// any forwarded host provided by an untrusted remote request.
export function browserControlAPIURL(pageURL: string): string {
  const page = new URL(pageURL)
  if (page.protocol !== 'http:' && page.protocol !== 'https:') return ''
  const loopback = page.hostname === 'localhost' || page.hostname === '127.0.0.1' || page.hostname === '[::1]'
  const scheme = loopback ? page.protocol : 'https:'
  return `${scheme}//${page.host}/api`
}
