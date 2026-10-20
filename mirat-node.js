// Minimal Mirat runtime error reporter for Node.js (built-in modules only).
// Usage: const mirat = require('./mirat-node'); mirat.init(process.env.MIRAT_DSN);
'use strict';
const http = require('http');
const https = require('https');
const { URL } = require('url');
let dsn = '';
let environment = 'production';
let release = '';

function post(event) {
  if (!dsn) return;
  try {
    const target = new URL(dsn);
    const transport = target.protocol === 'https:' ? https : http;
    const body = Buffer.from(JSON.stringify(event));
    const req = transport.request({
      protocol: target.protocol, hostname: target.hostname, port: target.port || undefined,
      path: target.pathname + target.search, method: 'POST', timeout: 2000,
      headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Content-Length': body.length }
    }, res => res.resume());
    req.on('error', () => {});
    req.on('timeout', () => req.destroy());
    req.end(body);
  } catch (_) { /* Reporting must not replace an application error. */ }
}

function captureException(error, extra = {}) {
  const err = error instanceof Error ? error : new Error(String(error));
  post({
    type: err.name || 'Error', message: String(err.message || err).slice(0, 1000),
    stacktrace: String(err.stack || '').slice(0, 12000), culprit: '', level: 'error',
    environment, release, timestamp: new Date().toISOString(), extra
  });
}

function init(endpoint, options = {}) {
  dsn = String(endpoint || '');
  environment = String(options.environment || 'production');
  release = String(options.release || '');
  if (!dsn) return;
  if (typeof process.on === 'function') {
    if (process.listenerCount('uncaughtExceptionMonitor') >= 0) {
      // This monitor observes uncaught errors without changing Node's default exit behavior.
      process.on('uncaughtExceptionMonitor', error => captureException(error, { mechanism: 'uncaughtException' }));
    }
    process.on('unhandledRejection', reason => captureException(reason, { mechanism: 'unhandledRejection' }));
  }
}

module.exports = { init, captureException };
