'use strict';

const http = require('http');
const { URL } = require('url');

function createApp() {
  const middlewares = [];
  const routes = [];

  function matchPath(pattern, actualPath) {
    const pParts = pattern.split('/').filter(Boolean);
    const aParts = actualPath.split('/').filter(Boolean);
    if (pParts.length !== aParts.length) return null;
    const params = {};
    for (let i = 0; i < pParts.length; i++) {
      if (pParts[i].startsWith(':')) {
        params[pParts[i].slice(1)] = decodeURIComponent(aParts[i]);
      } else if (pParts[i] !== aParts[i]) {
        return null;
      }
    }
    return params;
  }

  function enhanceRes(res) {
    res.statusCode = 200;
    res.status = function (code) {
      res.statusCode = code;
      return res;
    };
    res.set = function (k, v) {
      res.setHeader(k, v);
      return res;
    };
    res.json = function (obj) {
      if (!res.headersSent) {
        res.setHeader('Content-Type', 'application/json; charset=utf-8');
      }
      res.end(JSON.stringify(obj));
      return res;
    };
    res.send = function (body) {
      if (Buffer.isBuffer(body)) {
        res.end(body);
      } else if (typeof body === 'object') {
        res.json(body);
      } else {
        if (!res.headersSent) {
          res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        }
        res.end(String(body));
      }
      return res;
    };
    return res;
  }

  function parseBody(req) {
    return new Promise((resolve, reject) => {
      const chunks = [];
      let total = 0;
      const MAX_BYTES = 15 * 1024 * 1024; // 15MB max audio upload
      req.on('data', (chunk) => {
        total += chunk.length;
        if (total > MAX_BYTES) {
          reject(new Error('PAYLOAD_TOO_LARGE'));
          req.destroy();
          return;
        }
        chunks.push(chunk);
      });
      req.on('end', () => {
        const raw = Buffer.concat(chunks);
        req.rawBody = raw;
        const ct = (req.headers['content-type'] || '').toLowerCase();
        if (raw.length === 0) {
          req.body = {};
          return resolve();
        }
        if (ct.includes('application/json')) {
          try {
            req.body = JSON.parse(raw.toString('utf8'));
            return resolve();
          } catch {
            return reject(new Error('INVALID_JSON'));
          }
        }
        req.body = raw;
        resolve();
      });
      req.on('error', reject);
    });
  }

  async function handler(req, res) {
    enhanceRes(res);
    const parsedUrl = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    req.path = parsedUrl.pathname;
    req.query = Object.fromEntries(parsedUrl.searchParams.entries());
    req.ip = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '127.0.0.1').split(',')[0].trim();

    try {
      await parseBody(req);
    } catch (err) {
      return res.status(err.message === 'PAYLOAD_TOO_LARGE' ? 413 : 400).json({
        error: err.message || 'Bad Request'
      });
    }

    let idx = 0;
    const runMiddleware = async () => {
      if (idx < middlewares.length) {
        const mw = middlewares[idx++];
        await new Promise((resolve, reject) => {
          let nextCalled = false;
          const next = (err) => {
            if (nextCalled) return;
            nextCalled = true;
            if (err) reject(err);
            else resolve();
          };
          Promise.resolve(mw(req, res, next)).catch(reject);
        });
        if (!res.writableEnded) {
          await runMiddleware();
        }
      }
    };

    try {
      await runMiddleware();
      if (res.writableEnded) return;

      for (const route of routes) {
        if (route.method === req.method) {
          const params = matchPath(route.path, req.path);
          if (params) {
            req.params = params;
            for (const fn of route.handlers) {
              let moveNext = false;
              await new Promise((resolve, reject) => {
                const next = (err) => {
                  if (err) return reject(err);
                  moveNext = true;
                  resolve();
                };
                Promise.resolve(fn(req, res, next))
                  .then(() => {
                    if (!moveNext && res.writableEnded) resolve();
                    else if (!moveNext) resolve();
                  })
                  .catch(reject);
              });
              if (res.writableEnded || !moveNext) break;
            }
            if (!res.writableEnded) {
              res.end();
            }
            return;
          }
        }
      }

      if (!res.writableEnded) {
        res.status(404).json({ error: 'Not Found', path: req.path });
      }
    } catch (err) {
      if (!res.writableEnded) {
        res.status(err.statusCode || 500).json({
          error: err.message || 'Internal Server Error'
        });
      }
    }
  }

  handler.use = (fn) => middlewares.push(fn);
  ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'].forEach((method) => {
    handler[method.toLowerCase()] = (path, ...handlers) => {
      routes.push({ method, path, handlers });
    };
  });

  handler.listen = (port, cb) => {
    const server = http.createServer(handler);
    return server.listen(port, cb);
  };

  return handler;
}

module.exports = { createApp };
