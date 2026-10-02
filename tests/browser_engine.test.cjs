const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const assert = require("node:assert/strict");

const engine = require("../lurescope/static/browser-engine.js");
const model = JSON.parse(fs.readFileSync(path.join(__dirname, "../space/model.json"), "utf8"));
engine.setModel(model);

const phishing = "Dear customer, verify your account within 24 hours or it will be suspended. Confirm now at https://example.test/login.";
const benign = "Hi team, the design review moved to Thursday at 2 PM. Please add comments to the shared project folder.";

test("heuristic Unicode boundaries, decimal digits, and case folding match Python anchors", () => {
  for (const text of ['urgentа', 'аurgent', '中urgent', 'urgent²', '_urgent']) {
    assert.equal(engine.scoreMessage(text, 'heuristic-v0').fraud_probability,
      engine.scoreMessage('ordinary notes', 'heuristic-v0').fraud_probability);
  }
  for (const [variant, original] of [['within ٢ hours', 'within 2 hours'],
    ['ſign in', 'sign in'], ['İnvoice', 'invoice'], ['ınvoice', 'invoice'], ['your banK', 'your bank']]) {
    assert.deepEqual(engine.scoreMessage(variant, 'heuristic-v0').signals,
      engine.scoreMessage(original, 'heuristic-v0').signals);
    assert.equal(engine.scoreMessage(variant, 'heuristic-v0').fraud_probability,
      engine.scoreMessage(original, 'heuristic-v0').fraud_probability);
  }
});

test("quoted-printable never replaces invalid UTF-8 or splits supplementary characters", () => {
  const prefix = 'Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n';
  for (const body of ['=FF', '=C0=AF', '=ED=A0=80', '=E2=82', '\ud800']) {
    assert.throws(() => engine.triageEmail(prefix + body), /encoded data|Unicode/i);
  }
  for (const body of ['Please review 📄 notes.', 'Please review =F0=9F=93=84 notes.']) {
    const actual = engine.triageEmail(prefix + body, 'heuristic-v0');
    const expected = engine.triageEmail('\r\nPlease review 📄 notes.', 'heuristic-v0');
    assert.equal(actual.content_probability, expected.content_probability);
  }
});

test("browser TF-IDF model ranks the phishing sample above the benign sample", () => {
  const fraud = engine.scoreMessage(phishing, "tfidf-logreg");
  const normal = engine.scoreMessage(benign, "tfidf-logreg");

  assert.ok(fraud.fraud_probability > normal.fraud_probability);
  assert.equal(fraud.threshold_source, "browser-default");
  assert.ok(fraud.signals.length > 0);
});

test("HTML numeric references are decoded once before scoring and link extraction", () => {
  const prefix = 'Content-Type: text/html; charset=utf-8\r\n\r\n';
  const message = 'Urgent: verify your account within 24 hours.';
  for (const encoded of [Array.from(message, c => `&#${c.codePointAt(0)};`).join(''),
    Array.from(message, c => `&#x${c.codePointAt(0).toString(16)};`).join('')]) {
    assert.equal(engine.triageEmail(prefix + '<p>' + encoded + '</p>', 'heuristic-v0').content_probability,
      engine.scoreMessage(message, 'heuristic-v0').fraud_probability);
  }
  const actual = engine.triageEmail(prefix + '<p>Please review &#x1F4C4; notes.</p>' +
    '<a href="&#104;ttps://example.org/?a=1&amp;b=2">Portal</a>', 'heuristic-v0');
  assert.deepEqual(actual.urls, ['https://example.org/?a=1&b=2']);
  const once = engine.triageEmail(prefix + '<p>&amp;#117;rgent</p>', 'heuristic-v0');
  assert.equal(once.content_probability, engine.scoreMessage('&#117;rgent', 'heuristic-v0').fraud_probability);
});

test("unsupported or invalid HTML references require the API rather than partial scoring", () => {
  for (const reference of ['&Tab;', '&copy;', '&amp', '&#0;', '&#xD800;', '&#1114112;',
    '&#128;', '&#11;', '&#xFFFF;', '&#xFDD0;', '&#999999999999999999999999999999;']) {
    assert.throws(() => engine.triageEmail('Content-Type: text/html\r\n\r\n' +
      '<p>Safe-looking notes ' + reference + '</p>', 'heuristic-v0'), /HTML character reference/);
  }
});

test("homoglyph normalization restores the original heuristic score", () => {
  const result = engine.attackMessage(phishing, "homoglyph", "heuristic-v0", "normalize");

  assert.notEqual(result.attacked, result.original);
  assert.equal(result.defended_text, result.original);
  assert.ok(Math.abs(result.defended_probability - result.clean_probability) < 1e-12);
  assert.equal(result.defense_recovered, result.evaded);
});

test("bounded email preview separates model output from deterministic context", () => {
  const raw = [
    "From: Billing <billing@example.com>",
    "Reply-To: collect@lookalike.example",
    "To: user@example.net",
    "Subject: Urgent invoice payment",
    "Message-ID: <preview-1@example.com>",
    "Authentication-Results: gateway.example; spf=fail; dkim=fail; dmarc=fail",
    "Content-Type: multipart/mixed; boundary=boundary-1",
    "",
    "--boundary-1",
    "Content-Type: text/plain; charset=utf-8",
    "",
    "Please process the attached invoice and sign in at http://192.0.2.7/login.",
    "--boundary-1",
    "Content-Type: application/octet-stream; name=invoice.exe",
    "Content-Disposition: attachment; filename=invoice.exe",
    "",
    "not-opened",
    "--boundary-1--",
  ].join("\r\n");

  const result = engine.triageEmail(raw, "heuristic-v0");
  const codes = new Set(result.evidence.map((item) => item.code));

  assert.equal(result.browser_preview, true);
  assert.equal(result.risk_tier, "high");
  assert.ok(codes.has("reply_to_domain_mismatch"));
  assert.ok(codes.has("email_authentication_failed"));
  assert.ok(codes.has("ip_literal_url"));
  assert.ok(codes.has("executable_attachment"));
  assert.deepEqual(result.attachments, ["invoice.exe"]);
});

test("oversized and content-free email inputs fail closed", () => {
  assert.throws(() => engine.triageEmail("From: a@example.test\r\n\r\n"), /no subject or readable text/i);
  assert.throws(() => engine.scoreMessage("x".repeat(engine.MAX_TEXT + 1)), /character limit/i);
});

test("filename-bearing parts never contribute text or links regardless of disposition", () => {
  const expected = engine.triageEmail('Subject: Notes\r\n\r\nOuter notes only.', 'heuristic-v0');
  for (const headers of [
    'Content-Type: text/plain; name="attached.txt"',
    'Content-Type: text/html; name="attached.html"\r\nContent-Disposition: inline',
    'Content-Type: text/plain\r\nContent-Disposition: inline; filename=""',
    'Content-Type: multipart/mixed; name="attached.eml"',
  ]) {
    const raw = 'Subject: Notes\r\nContent-Type: multipart/mixed; boundary=part\r\n\r\n' +
      '--part\r\nContent-Type: text/plain\r\n\r\nOuter notes only.\r\n' +
      '--part\r\n' + headers + '\r\nContent-Transfer-Encoding: unsupported\r\n\r\n' +
      'Urgent verify your account https://127.0.0.1/private\r\n--part--\r\n';
    const result = engine.triageEmail(raw, 'heuristic-v0');
    assert.equal(result.content_probability, expected.content_probability);
    assert.deepEqual(result.urls, []);
  }
  const top = engine.triageEmail('Subject: Notes\r\nContent-Type: multipart/mixed; name="attached.eml"' +
    '\r\n\r\nNot a body or a valid multipart boundary', 'heuristic-v0');
  assert.deepEqual(top.attachments, ['attached.eml']);
  assert.equal(top.content_probability, engine.triageEmail('Subject: Notes\r\n\r\n', 'heuristic-v0').content_probability);
});

test("extended filename parameters require full API instead of silent partial interpretation", () => {
  for (const header of ["Content-Type: text/plain; name*=utf-8''private.txt",
    "Content-Disposition: inline; filename*0=private; filename*1=.txt"]) {
    assert.throws(() => engine.triageEmail('Subject: Notes\r\n' + header + '\r\n\r\nprivate text'),
      /Extended MIME parameters/);
  }
});

test("malformed links produce review evidence without losing other domain checks", () => {
  for (const url of ['http://[broken', 'http://[not-an-ip]/']) {
    const result = engine.triageEmail('Subject: Notes\r\n\r\nReview ' + url +
      ' and https://127.0.0.1/notes', 'heuristic-v0');
    const codes = new Set(result.evidence.map(item => item.code));
    assert.ok(codes.has('malformed_url'));
    assert.ok(codes.has('ip_literal_url'));
    assert.ok(['review', 'high'].includes(result.risk_tier));
    const detail = result.evidence.find(item => item.code === 'malformed_url').detail;
    assert.ok(detail.includes('1 extracted link'));
    assert.ok(!detail.includes(url));
  }
});

test("packaged browser model is identical to the static Space artifact", () => {
  assert.deepEqual(fs.readFileSync(path.join(__dirname, "../lurescope/static/model.json")),
    fs.readFileSync(path.join(__dirname, "../space/model.json")));
});

test("prototype-shaped message tokens do not crash or supply inherited weights", () => {
  const result = engine.scoreMessage("__proto__ constructor hasownproperty");
  assert.ok(Number.isFinite(result.fraud_probability));
  assert.ok(result.fraud_probability >= 0 && result.fraud_probability <= 1);
});

test("model installation validates every weight and preserves the old model on failure", () => {
  const before = engine.scoreMessage(phishing);
  const valid = {intercept: 0, ngram_max: 1, sublinear_tf: true, norm: "l2", vocab: {hello: [1, 2]}};
  for (const patch of [
    {intercept: NaN}, {intercept: Infinity}, {ngram_max: 0}, {ngram_max: 4},
    {ngram_max: 1.5}, {norm: "l1"}, {sublinear_tf: "true"}, {vocab: {}},
    {vocab: []}, {vocab: {hello: [0, 2]}}, {vocab: {hello: [1, Infinity]}},
    {vocab: {hello: [1e100, 2]}}, {vocab: {hello: [1]}},
  ]) assert.throws(() => engine.setModel({...valid, ...patch}), /Invalid browser model/);
  assert.deepEqual(engine.scoreMessage(phishing), before);
});

test("installed vocabulary is detached, immutable, and handles own prototype names", () => {
  const input = {intercept: 0, ngram_max: 1, sublinear_tf: true, norm: "l2",
    vocab: JSON.parse('{"__proto__":[1,2],"constructor":[1,-2]}')};
  try {
    const installed = engine.setModel(input);
    assert.equal(Object.getPrototypeOf(installed.vocab), null);
    assert.ok(Object.isFrozen(installed.vocab.__proto__));
    input.vocab.__proto__[1] = -100;
    input.intercept = -100;
    assert.ok(engine.scoreMessage("__proto__").fraud_probability > 0.8);
    assert.ok(engine.scoreMessage("constructor").fraud_probability < 0.2);
    assert.equal(engine.scoreMessage("unknown").fraud_probability, 0.5);
  } finally { engine.setModel(model); }
});

test("thresholds cannot coerce or silently turn invalid numbers into benign decisions", () => {
  for (const threshold of [NaN, Infinity, -0.1, 1.1, "0.5", null]) {
    assert.throws(() => engine.scoreMessage(phishing, "tfidf-logreg", threshold), /Threshold/);
  }
  assert.equal(engine.scoreMessage(phishing, "tfidf-logreg", 0.9).threshold_source, "browser-override");
});

test("long email text is not silently truncated into a low-risk result", () => {
  assert.throws(() => engine.triageEmail("Subject: Synthetic\r\n\r\n" + "a".repeat(engine.MAX_TEXT)),
    /scoring limit/);
});

test("unsupported MIME bodies and encodings do not become partial benign assessments", () => {
  for (const headers of [
    "Content-Type: multipart/mixed",
    'Content-Type: multipart/encrypted; boundary="b"',
    "Content-Type: message/rfc822",
    "Content-Type: application/octet-stream",
    "Content-Type: text/plain; charset=iso-8859-1",
    "Content-Transfer-Encoding: unknown",
    "Content-Type: text/plain\r\nContent-Type: text/html",
    "Content-Type: text/plain; charset=utf-8; charset=us-ascii",
  ]) assert.throws(() => engine.triageEmail("Subject: Friendly reminder\r\n" + headers + "\r\n\r\nhello"),
    /Unsupported|Ambiguous|Duplicate/);
  const nested = 'Subject: Friendly reminder\r\nContent-Type: multipart/mixed; boundary="b"\r\n\r\n' +
    '--b\r\nContent-Type: multipart/alternative; boundary="inner"\r\n\r\n' +
    '--inner\r\n\r\nsynthetic message\r\n--inner--\r\n--b--';
  assert.throws(() => engine.triageEmail(nested), /nested MIME/);
});

test("MIME boundaries must delimit complete lines and include a closing boundary", () => {
  const header = 'Content-Type: multipart/mixed; boundary="b.+"\r\n\r\n';
  const content = 'hello x--b.+ is body text\r\nPlease verify your account immediately';
  const raw = header + '--b.+\r\n\r\n' + content + '\r\n--b.+--';
  const result = engine.triageEmail(raw, "heuristic-v0");
  assert.equal(result.content_probability, engine.scoreMessage(content, "heuristic-v0").fraud_probability);
  assert.throws(() => engine.triageEmail(raw.replace('--b.+--', '')), /Incomplete multipart/);
  assert.throws(() => engine.triageEmail(header + '--b.+--'), /Incomplete multipart/);
  assert.throws(() => engine.triageEmail('Content-Type: multipart/mixed; xboundary="b"\r\n\r\n--b--'),
    /Unsupported multipart boundary/);
});

test("too many MIME parts fail before returning a score", () => {
  const raw = 'Content-Type: multipart/mixed; boundary="b"\r\n\r\n' +
    '--b\r\n\r\nhello\r\n'.repeat(129) + '--b--';
  assert.throws(() => engine.triageEmail(raw), /Too many MIME parts/);
});

test("transfer decoding agrees on strict text and rejects corrupt data", () => {
  const prefix = 'Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: ';
  const message = 'Please verify your account immediately';
  const encoded = Buffer.from(message).toString('base64');
  const expected = engine.scoreMessage(message, 'heuristic-v0').fraud_probability;
  assert.equal(engine.triageEmail(prefix + 'base64\r\n\r\n' + encoded, 'heuristic-v0').content_probability, expected);
  assert.equal(engine.triageEmail(prefix + 'quoted-printable\r\n\r\n' + message.replaceAll(' ', '=20'), 'heuristic-v0').content_probability, expected);
  for (const corrupt of ['not base64!', 'a', '====', 'YWJj=']) {
    assert.throws(() => engine.triageEmail(prefix + 'base64\r\n\r\n' + corrupt), /base64/);
  }
  assert.throws(() => engine.triageEmail(prefix + 'quoted-printable\r\n\r\nhello=GG'), /quoted-printable/);
  const long = Buffer.from('a'.repeat(500_000)).toString('base64');
  assert.throws(() => engine.triageEmail(prefix + 'base64\r\n\r\n' + long), /scoring limit/);
});
