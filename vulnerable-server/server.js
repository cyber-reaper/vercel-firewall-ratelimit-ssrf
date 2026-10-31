const http = require('http');
const { unstable_checkRateLimit: checkRateLimit } = require('@vercel/firewall');

process.env.NODE_ENV = 'production';
process.env.VERCEL_AUTOMATION_BYPASS_SECRET = 'secret_bypass_abc123';
process.env.RATE_LIMIT_SECRET = 'rate_limit_secret_xyz789';

// Intercept fetch to downgrade HTTPS to HTTP for local testing.
// In production the URL is HTTPS and the attacker just needs a valid cert.
const originalFetch = globalThis.fetch;
globalThis.fetch = async function (url, opts) {
  const localUrl = url.toString().replace('https://', 'http://');
  return originalFetch(localUrl, opts);
};

const server = http.createServer(async (req, res) => {
  try {
    const result = await checkRateLimit('rl-test', {
      headers: req.headers,
    });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(result));
  } catch (err) {
    res.writeHead(500);
    res.end(err.message);
  }
});

const port = process.env.PORT || 3000;
server.listen(port, () => {
  console.log(`[*] Vulnerable server on :${port} (using @vercel/firewall@1.2.6)`);
});
