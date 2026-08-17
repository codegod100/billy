'use strict';
// Minimal OIDC-validating reverse proxy in front of `docker-agent serve a2a`.
// docker-agent's A2A server has no auth of its own, so this terminates auth:
// verifies incoming Bearer JWTs against the issuer's JWKS (iss/aud/exp/sig),
// then forwards authenticated requests to the internal a2a listener.
//
// The one path exempted from auth is the agent-card discovery document
// (/.well-known/agent-card.json), per A2A convention — it's meant to be
// fetched by anyone before they authenticate. We rewrite its `url` field
// (which docker-agent bakes in from --listen, i.e. localhost) to our real
// public URL, and advertise the OIDC security scheme so A2A clients know
// how to authenticate.

const http = require('http');
const https = require('https');
const crypto = require('crypto');

const ISSUER = process.env.OIDC_ISSUER || 'https://id.openbao.boxd.sh';
const AUDIENCE = process.env.OIDC_AUDIENCE;
const JWKS_URL = process.env.OIDC_JWKS_URL || `${ISSUER}/.well-known/jwks.json`;
const UPSTREAM_HOST = process.env.UPSTREAM_HOST || '127.0.0.1';
const UPSTREAM_PORT = Number(process.env.UPSTREAM_PORT || 9091);
const LISTEN_PORT = Number(process.env.A2A_PUBLIC_PORT || 8090);
const PUBLIC_URL = process.env.PUBLIC_URL; // e.g. https://billy-a2a.up.railway.app

if (!AUDIENCE) {
  console.error('OIDC_AUDIENCE is required (expected `aud` claim / client_id)');
  process.exit(1);
}

const AGENT_CARD_PATH = '/.well-known/agent-card.json';

let jwksCache = { keys: [], fetchedAt: 0 };
const JWKS_TTL_MS = 10 * 60 * 1000;

function fetchJson(urlStr) {
  return new Promise((resolve, reject) => {
    https
      .get(urlStr, (res) => {
        if (res.statusCode < 200 || res.statusCode >= 300) {
          res.resume();
          return reject(new Error(`GET ${urlStr} -> ${res.statusCode}`));
        }
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => {
          try {
            resolve(JSON.parse(data));
          } catch (e) {
            reject(e);
          }
        });
      })
      .on('error', reject);
  });
}

async function getJwks(forceRefresh) {
  if (!forceRefresh && Date.now() - jwksCache.fetchedAt < JWKS_TTL_MS && jwksCache.keys.length) {
    return jwksCache.keys;
  }
  const jwks = await fetchJson(JWKS_URL);
  jwksCache = { keys: jwks.keys || [], fetchedAt: Date.now() };
  return jwksCache.keys;
}

function b64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64');
}

const ALG_TO_NODE = {
  RS256: 'RSA-SHA256',
  RS384: 'RSA-SHA384',
  RS512: 'RSA-SHA512',
  PS256: 'RSA-SHA256',
  ES256: 'sha256',
  ES384: 'sha384',
  ES512: 'sha512',
};

async function verifyJwt(token) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('malformed token');
  const [headerB64, payloadB64, sigB64] = parts;
  const header = JSON.parse(b64urlDecode(headerB64));
  const payload = JSON.parse(b64urlDecode(payloadB64));

  if (!header.kid) throw new Error('token missing kid');
  const nodeAlg = ALG_TO_NODE[header.alg];
  if (!nodeAlg) throw new Error(`unsupported alg: ${header.alg}`);

  let keys = await getJwks(false);
  let jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) {
    // kid not in cache — could be a just-rotated key, refresh once and retry
    keys = await getJwks(true);
    jwk = keys.find((k) => k.kid === header.kid);
  }
  if (!jwk) throw new Error('no matching JWKS key for kid');

  const publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  const signingInput = `${headerB64}.${payloadB64}`;
  const signature = b64urlDecode(sigB64);

  const verifyOpts = header.alg.startsWith('ES')
    ? { key: publicKey, dsaEncoding: 'ieee-p1363' }
    : publicKey;
  const ok = crypto.verify(nodeAlg, Buffer.from(signingInput), verifyOpts, signature);
  if (!ok) throw new Error('bad signature');

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && now >= payload.exp) throw new Error('token expired');
  if (payload.nbf && now < payload.nbf) throw new Error('token not yet valid');
  if (payload.iss !== ISSUER) throw new Error(`unexpected iss: ${payload.iss}`);

  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!aud.includes(AUDIENCE)) throw new Error(`unexpected aud: ${JSON.stringify(payload.aud)}`);

  return payload;
}

function proxyRequest(req, res, extraHeaders) {
  const proxyReq = http.request(
    {
      host: UPSTREAM_HOST,
      port: UPSTREAM_PORT,
      path: req.url,
      method: req.method,
      headers: { ...req.headers, ...extraHeaders },
    },
    (proxyRes) => {
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(res);
    }
  );
  proxyReq.on('error', (err) => {
    res.writeHead(502, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'upstream unreachable', detail: err.message }));
  });
  req.pipe(proxyReq);
}

// ─── A2A REST-binding <-> docker-agent JSON-RPC translation ────────────────
//
// docker-agent only implements the A2A *JSON-RPC* transport binding: a
// single POST /invoke endpoint, method dispatched via a `method` field in
// the body, lowercase string enums (role: "user", state: "completed"). Some
// A2A clients (e.g. orchestral) instead speak the REST/HTTP+JSON binding:
// separate POST {base}/message:send and POST {base}/message:stream
// endpoints, flat request/response bodies, protobuf-style SCREAMING_SNAKE
// enums (role: "ROLE_USER", state: "TASK_STATE_COMPLETED") — both are
// legitimate A2A wire formats for the same protocol, docker-agent just only
// implemented one of them. These handlers translate REST-binding requests
// into JSON-RPC calls against the upstream, and translate the JSON-RPC
// responses back into REST-binding shape.

const ROLE_UPSTREAM_TO_REST = { user: 'ROLE_USER', agent: 'ROLE_AGENT' };
const ROLE_REST_TO_UPSTREAM = { ROLE_USER: 'user', ROLE_AGENT: 'agent' };
const STATE_UPSTREAM_TO_REST = {
  submitted: 'TASK_STATE_SUBMITTED',
  working: 'TASK_STATE_WORKING',
  'input-required': 'TASK_STATE_INPUT_REQUIRED',
  completed: 'TASK_STATE_COMPLETED',
  failed: 'TASK_STATE_FAILED',
  canceled: 'TASK_STATE_CANCELED',
  cancelled: 'TASK_STATE_CANCELED',
  rejected: 'TASK_STATE_REJECTED',
  'auth-required': 'TASK_STATE_AUTH_REQUIRED',
};
const KIND_TO_REST_KEY = {
  task: 'task',
  message: 'message',
  'status-update': 'statusUpdate',
  'artifact-update': 'artifactUpdate',
};

// Recursively rewrite every `role`/`state` value found anywhere in a
// JSON-RPC result (Task, Message, status/artifact update events all nest
// these at different depths) into the REST binding's enum spelling.
function mapEnumsToRest(value) {
  if (Array.isArray(value)) return value.map(mapEnumsToRest);
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (k === 'role' && typeof v === 'string' && ROLE_UPSTREAM_TO_REST[v]) {
        out[k] = ROLE_UPSTREAM_TO_REST[v];
      } else if (k === 'state' && typeof v === 'string') {
        out[k] = STATE_UPSTREAM_TO_REST[v] || 'TASK_STATE_UNKNOWN';
      } else {
        out[k] = mapEnumsToRest(v);
      }
    }
    return out;
  }
  return value;
}

function mapMessageToUpstream(message) {
  if (!message || typeof message !== 'object') return message;
  const out = { ...message };
  if (out.role && ROLE_REST_TO_UPSTREAM[out.role]) out.role = ROLE_REST_TO_UPSTREAM[out.role];
  return out;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => (data += c));
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

function rpcRequestOptions() {
  return { host: UPSTREAM_HOST, port: UPSTREAM_PORT, path: '/invoke', method: 'POST' };
}

// Non-streaming JSON-RPC call: buffers and returns the parsed response.
function rpcCallJson(method, params) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ jsonrpc: '2.0', id: crypto.randomUUID(), method, params });
    const proxyReq = http.request(
      { ...rpcRequestOptions(), headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } },
      (proxyRes) => {
        let data = '';
        proxyRes.on('data', (c) => (data += c));
        proxyRes.on('end', () => {
          try {
            resolve(JSON.parse(data));
          } catch (e) {
            reject(e);
          }
        });
      }
    );
    proxyReq.on('error', reject);
    proxyReq.end(body);
  });
}

// Streaming JSON-RPC call: resolves with the raw upstream response so the
// caller can pump SSE chunks as they arrive.
function rpcCallStream(method, params) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ jsonrpc: '2.0', id: crypto.randomUUID(), method, params });
    const proxyReq = http.request(
      {
        ...rpcRequestOptions(),
        headers: {
          'content-type': 'application/json',
          accept: 'text/event-stream',
          'content-length': Buffer.byteLength(body),
        },
      },
      resolve
    );
    proxyReq.on('error', reject);
    proxyReq.end(body);
  });
}

async function handleMessageSend(req, res) {
  const raw = await readBody(req);
  let request;
  try {
    request = JSON.parse(raw);
  } catch (e) {
    res.writeHead(400, { 'content-type': 'application/json' });
    return res.end(JSON.stringify({ error: 'invalid JSON body', detail: e.message }));
  }

  const params = { ...request, message: mapMessageToUpstream(request.message) };
  let rpcRes;
  try {
    rpcRes = await rpcCallJson('message/send', params);
  } catch (err) {
    res.writeHead(502, { 'content-type': 'application/json' });
    return res.end(JSON.stringify({ error: 'upstream unreachable', detail: err.message }));
  }

  if (rpcRes.error) {
    res.writeHead(500, { 'content-type': 'application/json' });
    return res.end(JSON.stringify({ error: rpcRes.error.message || 'upstream error', detail: rpcRes.error }));
  }

  const result = mapEnumsToRest(rpcRes.result);
  const key = KIND_TO_REST_KEY[result.kind] || 'task';
  res.writeHead(200, { 'content-type': 'application/a2a+json' });
  res.end(JSON.stringify({ [key]: result }));
}

async function handleMessageStream(req, res) {
  const raw = await readBody(req);
  let request;
  try {
    request = JSON.parse(raw);
  } catch (e) {
    res.writeHead(400, { 'content-type': 'application/json' });
    return res.end(JSON.stringify({ error: 'invalid JSON body', detail: e.message }));
  }

  const params = { ...request, message: mapMessageToUpstream(request.message) };
  let upstreamRes;
  try {
    upstreamRes = await rpcCallStream('message/stream', params);
  } catch (err) {
    res.writeHead(502, { 'content-type': 'application/json' });
    return res.end(JSON.stringify({ error: 'upstream unreachable', detail: err.message }));
  }

  res.writeHead(200, {
    'content-type': 'text/event-stream',
    'cache-control': 'no-cache',
    connection: 'keep-alive',
  });

  let buffer = '';
  upstreamRes.on('data', (chunk) => {
    buffer += chunk.toString('utf8');
    const events = buffer.split('\n\n');
    buffer = events.pop() || '';
    for (const event of events) {
      for (const line of event.split('\n')) {
        if (!line.startsWith('data: ')) continue;
        let parsed;
        try {
          parsed = JSON.parse(line.slice(6));
        } catch {
          continue;
        }
        if (parsed.error) {
          res.write(`data: ${JSON.stringify({ error: parsed.error })}\n\n`);
          continue;
        }
        const result = mapEnumsToRest(parsed.result);
        const key = KIND_TO_REST_KEY[result.kind] || 'task';
        res.write(`data: ${JSON.stringify({ [key]: result })}\n\n`);
      }
    }
  });
  upstreamRes.on('end', () => res.end());
  upstreamRes.on('error', (err) => {
    res.write(`data: ${JSON.stringify({ error: { message: err.message } })}\n\n`);
    res.end();
  });
}

async function serveAgentCard(req, res) {
  try {
    const card = await fetchLocalJson(`http://${UPSTREAM_HOST}:${UPSTREAM_PORT}${AGENT_CARD_PATH}`);
    if (PUBLIC_URL) {
      // Bare base, not .../invoke — REST-binding clients (e.g. orchestral)
      // append /message:send and /message:stream directly onto this url.
      card.url = PUBLIC_URL.replace(/\/$/, '');
    }
    // A2A's SecurityScheme is a protobuf oneof — in JSON that's a nested
    // wrapper key per scheme type (openIdConnectSecurityScheme, etc.), not
    // a flat {type, ...} object. And openIdConnectUrl is the bare issuer;
    // OIDC clients append /.well-known/openid-configuration themselves.
    card.securitySchemes = {
      ...(card.securitySchemes || {}),
      'pocket-id-oidc': {
        openIdConnectSecurityScheme: {
          type: 'openIdConnect',
          openIdConnectUrl: ISSUER,
        },
      },
    };
    card.security = [{ 'pocket-id-oidc': [] }];
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(card));
  } catch (err) {
    res.writeHead(502, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'failed to load agent card', detail: err.message }));
  }
}

function fetchLocalJson(urlStr) {
  return new Promise((resolve, reject) => {
    http
      .get(urlStr, (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => {
          try {
            resolve(JSON.parse(data));
          } catch (e) {
            reject(e);
          }
        });
      })
      .on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  const path = (req.url || '').split('?')[0];

  // Agent card is public discovery — no auth, per A2A convention.
  if (path === AGENT_CARD_PATH && req.method === 'GET') {
    return serveAgentCard(req, res);
  }

  const auth = req.headers['authorization'] || '';
  const m = /^Bearer\s+(.+)$/i.exec(auth);
  if (!m) {
    res.writeHead(401, { 'content-type': 'application/json', 'www-authenticate': 'Bearer' });
    return res.end(JSON.stringify({ error: 'missing bearer token' }));
  }

  let claims;
  try {
    claims = await verifyJwt(m[1]);
  } catch (err) {
    res.writeHead(401, { 'content-type': 'application/json', 'www-authenticate': 'Bearer error="invalid_token"' });
    return res.end(JSON.stringify({ error: 'invalid token', detail: err.message }));
  }

  if (path === '/message:send' && req.method === 'POST') {
    return handleMessageSend(req, res);
  }
  if (path === '/message:stream' && req.method === 'POST') {
    return handleMessageStream(req, res);
  }

  proxyRequest(req, res, { 'x-oidc-subject': claims.sub || '', 'x-oidc-email': claims.email || '' });
});

server.listen(LISTEN_PORT, '0.0.0.0', () => {
  console.log(`OIDC-validating A2A proxy listening on :${LISTEN_PORT}`);
  console.log(`  forwarding to  -> http://${UPSTREAM_HOST}:${UPSTREAM_PORT}`);
  console.log(`  expecting      -> iss=${ISSUER} aud=${AUDIENCE}`);
  console.log(`  public card at -> ${PUBLIC_URL || '(PUBLIC_URL not set — agent card url will be wrong)'}${AGENT_CARD_PATH}`);
});
