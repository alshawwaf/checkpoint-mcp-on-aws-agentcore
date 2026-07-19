#!/usr/bin/env node
// Minimal MCP stdio client: spawns a server, does initialize -> initialized -> tools/list,
// prints the negotiated protocol + serverInfo + the tool catalog, then exits.
// Usage: node mcp_probe.mjs <npm-package> [--call <toolName> <jsonArgs>]
import { spawn } from 'node:child_process';

const pkg = process.argv[2];
if (!pkg) { console.error('usage: node mcp_probe.mjs <@chkp/pkg> [--call tool jsonArgs]'); process.exit(2); }
const callIdx = process.argv.indexOf('--call');
const callTool = callIdx > -1 ? process.argv[callIdx + 1] : null;
const callArgs = callIdx > -1 ? JSON.parse(process.argv[callIdx + 2] || '{}') : null;
// Anything between the package and --call is passed through to the server.
const serverArgs = process.argv.slice(3, callIdx > -1 ? callIdx : undefined);

const child = spawn('npx', ['-y', pkg, ...serverArgs], {
  stdio: ['pipe', 'pipe', 'pipe'],
  env: { ...process.env, TELEMETRY_DISABLED: 'true' },
});

let buf = '';
const pending = new Map();
let nextId = 1;
const send = (method, params) => {
  const id = nextId++;
  const msg = { jsonrpc: '2.0', id, method, ...(params ? { params } : {}) };
  child.stdin.write(JSON.stringify(msg) + '\n');
  return new Promise((res) => pending.set(id, res));
};
const notify = (method, params) => {
  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method, ...(params ? { params } : {}) }) + '\n');
};

child.stdout.on('data', (d) => {
  buf += d.toString();
  let nl;
  while ((nl = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, nl).trim();
    buf = buf.slice(nl + 1);
    if (!line) continue;
    let msg;
    try { msg = JSON.parse(line); } catch { continue; } // ignore non-JSON log lines
    if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
  }
});

const stderrLines = [];
child.stderr.on('data', (d) => stderrLines.push(d.toString()));
child.on('error', (e) => { console.error('SPAWN ERROR:', e.message); process.exit(1); });

const bail = setTimeout(() => {
  console.error('TIMEOUT after 90s. stderr tail:\n' + stderrLines.join('').slice(-1500));
  child.kill('SIGKILL');
  process.exit(1);
}, 90000);

(async () => {
  const init = await send('initialize', {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: { name: 'devhub-mcp-probe', version: '0.1.0' },
  });
  notify('notifications/initialized');
  console.log('=== initialize.result ===');
  console.log(JSON.stringify(init.result ?? init.error, null, 2));

  const list = await send('tools/list', {});
  const tools = list.result?.tools ?? [];
  console.log('\n=== tools/list ===  (' + tools.length + ' tools)');
  for (const t of tools) {
    const req = t.inputSchema?.required ?? [];
    const props = Object.keys(t.inputSchema?.properties ?? {});
    console.log(`\n• ${t.name}`);
    console.log(`    ${(t.description || '').replace(/\s+/g, ' ').slice(0, 160)}`);
    if (props.length) console.log(`    params: ${props.join(', ')}${req.length ? `  (required: ${req.join(', ')})` : ''}`);
  }

  if (callTool) {
    console.log(`\n=== tools/call ${callTool} ===`);
    const r = await send('tools/call', { name: callTool, arguments: callArgs });
    console.log(JSON.stringify(r.result ?? r.error, null, 2).slice(0, 3000));
  }

  clearTimeout(bail);
  child.kill('SIGTERM');
  process.exit(0);
})();
