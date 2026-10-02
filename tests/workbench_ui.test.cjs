"use strict";
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return {promise, resolve, reject};
}
const tick = () => new Promise(resolve => setImmediate(resolve));

function mount() {
  const html = fs.readFileSync(path.join(__dirname, '../lurescope/static/index.html'), 'utf8');
  const nodes = new Map();
  for (const match of html.matchAll(/id="([^"]+)"/g)) nodes.set(match[1], {
    value: '', textContent: '', innerHTML: '', style: {}, disabled: false, listeners: {},
    addEventListener(name, callback) { this.listeners[name] = callback; },
  });
  nodes.get('text').value = 'synthetic current message';
  nodes.get('detector').value = 'heuristic-v0';
  const requests = [], downloads = [];
  const context = vm.createContext({URLSearchParams, Blob, TextDecoder, btoa,
    URL: {createObjectURL: () => 'blob:synthetic', revokeObjectURL() {}},
    window: {location: {search: '', hostname: 'localhost', protocol: 'http:'},
      LureScopeEvidence: {parseArtifact: raw => JSON.parse(raw)}},
    document: {
      getElementById(id) { assert.ok(nodes.has(id), `unknown DOM ID: ${id}`); return nodes.get(id); },
      querySelectorAll() { return []; },
      body: {appendChild() {}},
      createElement() { return {click() { downloads.push(this.download); }, remove() {}}; },
    },
    fetch(route, options) {
      const pending = deferred();
      if (route !== 'capabilities') requests.push({route, options, ...pending,
        respond(data) { pending.resolve({ok: true, json: async () => data}); }});
      return pending.promise; // Initialization intentionally remains pending.
    },
  });
  const script = html.match(/<script>\s*([\s\S]*?)<\/script>/)[1];
  vm.runInContext(script, context);
  vm.runInContext('engineReady = true', context);
  return {nodes, requests, downloads, context, run: code => vm.runInContext(code, context)};
}

const score = probability => ({fraud_probability: probability, threshold: .5,
  label: probability >= .5 ? 'fraud' : 'benign', detector: 'heuristic-v0', signals: []});
const triage = subject => ({risk_tier: 'low', subject, from_address: 'synthetic@example.test',
  content_probability: .1, threshold: .5, evidence: [], recommended_action: 'Normal controls'});

test('editing message invalidates in-flight scoring and hides old results', async () => {
  const ui = mount();
  const pending = ui.run('analyze()');
  ui.nodes.get('text').value = 'different input';
  ui.nodes.get('text').listeners.input();
  ui.requests[0].respond(score(.99));
  await pending;
  assert.equal(ui.nodes.get('scoreResult').style.display, 'none');
  assert.equal(ui.nodes.get('scoreEmpty').style.display, 'block');
  assert.equal(ui.nodes.get('scoreBtn').disabled, false);
  assert.equal(ui.nodes.get('scoreErr').textContent, '');
});

test('older scoring responses and errors cannot overwrite newer results', async () => {
  for (const fail of [false, true]) {
    const ui = mount();
    const old = ui.run('analyze()');
    const latest = ui.run('analyze()');
    ui.requests[1].respond(score(.1));
    await latest;
    if (fail) ui.requests[0].reject(new Error('old failure'));
    else ui.requests[0].respond(score(.99));
    await old;
    assert.equal(ui.nodes.get('verdict').textContent, 'LIKELY BENIGN');
    assert.equal(ui.nodes.get('scoreErr').textContent, '');
  }
});

test('attack selection changes reject an in-flight old experiment', async () => {
  const ui = mount();
  const pending = ui.run('attack()');
  ui.nodes.get('attack').listeners.change();
  ui.requests[0].respond({});
  await pending;
  assert.equal(ui.nodes.get('attackResult').style.display, 'none');
  assert.equal(ui.nodes.get('attackErr').textContent, '');
});

test('slow file reading does not send a superseded email to the API', async () => {
  const ui = mount(), oldRead = deferred();
  ui.context.oldFile = {name: 'old.eml', size: 10, arrayBuffer: () => oldRead.promise};
  ui.context.newFile = {name: 'new.eml', size: 10, arrayBuffer: async () => Buffer.from('new raw email')};
  const old = ui.run('triageFile(oldFile)');
  const latest = ui.run('triageFile(newFile)');
  await tick();
  assert.equal(ui.requests.length, 1);
  assert.equal(Buffer.from(JSON.parse(ui.requests[0].options.body).raw_email_base64, 'base64').toString(), 'new raw email');
  ui.requests[0].respond(triage('new subject'));
  await latest;
  oldRead.resolve(Buffer.from('old raw email'));
  await old;
  assert.equal(ui.requests.length, 1);
  assert.equal(ui.nodes.get('triageSubject').textContent, 'new subject');
});

test('proof download remains bound to the triaged email and detector', async () => {
  const ui = mount();
  ui.context.file = {name: 'reviewed.eml', size: 10, arrayBuffer: async () => Buffer.from('reviewed message')};
  const pending = ui.run('triageFile(file)');
  await tick();
  ui.requests[0].respond(triage('reviewed subject'));
  await pending;
  const proof = ui.run('downloadProof()');
  assert.equal(JSON.parse(ui.requests[1].options.body).detector, 'heuristic-v0');
  ui.requests[1].respond({schema_version: 1});
  await proof;
  assert.deepEqual(ui.downloads, ['reviewed.lureproof.json']);
});

test('API file intake and proof use exact original bytes, including invalid UTF-8', async () => {
  const ui = mount();
  const original = Buffer.from([0x00, 0x41, 0xff, 0x80, 0x0d, 0x0a]);
  ui.context.file = {name: 'bytes.eml', size: original.length, arrayBuffer: async () => original};
  const pending = ui.run('triageFile(file)');
  await tick();
  const request = JSON.parse(ui.requests[0].options.body);
  assert.equal(request.raw_email, undefined);
  assert.deepEqual(Buffer.from(request.raw_email_base64, 'base64'), original);
  ui.requests[0].respond(triage('byte-preserved message'));
  await pending;
  const proof = ui.run('downloadProof()');
  assert.equal(JSON.parse(ui.requests[1].options.body).raw_email_base64, request.raw_email_base64);
  ui.requests[1].respond({schema_version: 1});
  await proof;
});

test('late triage response cannot replace a newer email assessment', async () => {
  const ui = mount();
  ui.context.first = {name: 'first.eml', size: 10, arrayBuffer: async () => Buffer.from('first raw')};
  ui.context.second = {name: 'second.eml', size: 10, arrayBuffer: async () => Buffer.from('second raw')};
  const first = ui.run('triageFile(first)');
  await tick();
  const second = ui.run('triageFile(second)');
  await tick();
  ui.requests[1].respond(triage('second subject'));
  await second;
  ui.requests[0].respond(triage('first subject'));
  await first;
  assert.equal(ui.nodes.get('triageSubject').textContent, 'second subject');
  assert.equal(ui.run('currentEmail.name'), 'second.eml');
});

test('clearing an evidence selection suppresses its delayed parse and errors', async () => {
  const ui = mount(), read = deferred();
  ui.context.file = {size: 10, arrayBuffer: () => read.promise};
  const old = ui.run('exploreEvidence(file)');
  await ui.run('exploreEvidence(null)');
  read.resolve(Buffer.from('invalid JSON must never be parsed'));
  await old;
  assert.equal(ui.nodes.get('evidenceErr').textContent, '');
  assert.equal(ui.nodes.get('evidenceResult').style.display, 'none');
});

test('evidence intake rejects invalid UTF-8 before the display parser', async () => {
  const ui = mount();
  let parsed = false;
  ui.context.window.LureScopeEvidence.parseArtifact = () => { parsed = true; return {}; };
  ui.context.file = {size: 1, arrayBuffer: async () => Buffer.from([255])};
  await ui.run('exploreEvidence(file)');
  assert.equal(parsed, false);
  assert.equal(ui.nodes.get('evidenceResult').style.display, 'none');
  assert.match(ui.nodes.get('evidenceErr').textContent, /encoded data/i);
  assert.equal(ui.requests.length, 0);
});

test('changing detector suppresses a delayed proof instead of downloading it under new context', async () => {
  const ui = mount();
  ui.context.file = {name: 'first.eml', size: 10, arrayBuffer: async () => Buffer.from('first raw')};
  const triaged = ui.run('triageFile(file)');
  await tick();
  ui.requests[0].respond(triage('first'));
  await triaged;
  const proof = ui.run('downloadProof()');
  ui.nodes.get('detector').value = 'tfidf-logreg';
  ui.nodes.get('detector').listeners.change();
  ui.requests[1].respond({schema_version: 1});
  await proof;
  assert.deepEqual(ui.downloads, []);
  assert.equal(ui.nodes.get('proofActions').style.display, 'none');
  assert.equal(ui.nodes.get('triageResult').style.display, 'none');
});
