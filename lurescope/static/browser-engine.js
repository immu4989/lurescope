/* LureScope's dependency-free browser engine.
 *
 * This module powers the GitHub Pages edition. The TF-IDF arithmetic and local
 * attacks mirror the Python implementation, while email parsing is deliberately
 * labeled as a bounded browser preview rather than the RFC-complete Python path.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  root.LureScopeBrowser = api;
}(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const THRESHOLD = 0.5;
  const MAX_TEXT = 20_000;
  const MAX_EMAIL_BYTES = 5 * 1024 * 1024;
  const TOKEN_RE = /[\p{L}\p{N}_]{2,}/gu;
  const URL_RE = /https?:\/\/[^\s<>"']+/gi;
  const DANGEROUS_EXTENSIONS = new Set([
    ".bat", ".cmd", ".com", ".exe", ".hta", ".iso", ".jar", ".js",
    ".lnk", ".msi", ".ps1", ".scr", ".vbe", ".vbs", ".wsf",
  ]);
  const ARCHIVE_EXTENSIONS = new Set([".7z", ".gz", ".img", ".rar", ".tar", ".zip"]);
  let model = null;

  const H_SIGNALS = [
    [/\b(urgent|immediately|right away|within \d+ (?:hours|minutes)|expire|suspend|final notice|act now|as soon as possible|asap|deadline|last chance)\b/i, 1.1, "urgency"],
    [/\b(it (?:support|department|team)|help ?desk|security team|your bank|account team|compliance|hr department|ceo|cfo|director|administrator)\b/i, 0.8, "authority"],
    [/\b(verify your (?:account|identity|password)|confirm your (?:details|password)|reset your password|login|log in|sign in|update your (?:payment|billing|account))\b/i, 1.3, "credential"],
    [/\b(wire transfer|gift ?card|bitcoin|crypto|usdt|bank details|routing number|invoice|payment|refund|prize|winnings|inheritance|beneficiary|investment)\b/i, 1.1, "payment"],
    [/(<<link>>|<<contact>>|https?:\/\/|wa\.me\/|t\.me\/|whatsapp|telegram)/i, 0.9, "handoff"],
    [/\b(do not tell|keep this (?:between us|confidential)|discreet|private matter)\b/i, 1.0, "secrecy"],
  ];
  const H_BIAS = -1.6;
  const HOMOGLYPHS = {a:"а",c:"с",e:"е",o:"о",p:"р",x:"х",y:"у",i:"і",s:"ѕ",j:"ј",A:"А",B:"В",C:"С",E:"Е",H:"Н",K:"К",M:"М",O:"О",P:"Р",T:"Т",X:"Х"};
  const LEET = {a:"4",e:"3",i:"1",o:"0",s:"5",t:"7",l:"1",b:"8"};
  const ZERO_WIDTH = "\u200b";
  const CONFUSABLES = {
    "а":"a","с":"c","е":"e","о":"o","р":"p","х":"x","у":"y","і":"i","ѕ":"s","ј":"j","ԁ":"d","һ":"h","ո":"n","ν":"v",
    "А":"A","В":"B","С":"C","Е":"E","Н":"H","К":"K","М":"M","О":"O","Р":"P","Т":"T","Х":"X","І":"I","Ѕ":"S","Ј":"J",
    "ο":"o","Ο":"O","Α":"A","Β":"B","Ε":"E","Ζ":"Z","Η":"H","Ι":"I","Κ":"K","Μ":"M","Ν":"N","Ρ":"P","Τ":"T","Υ":"Y","Χ":"X","ρ":"p","τ":"t","ι":"i",
  };
  const DELEET = {"4":"a","3":"e","0":"o","5":"s","7":"t","8":"b","1":"i"};

  function sigmoid(value) {
    return value < 0 ? Math.exp(value) / (1 + Math.exp(value)) : 1 / (1 + Math.exp(-value));
  }

  function tokens(text) {
    return text.toLowerCase().match(TOKEN_RE) || [];
  }

  function ngrams(items, nmax) {
    const result = items.slice();
    for (let n = 2; n <= nmax; n += 1) {
      for (let i = 0; i + n <= items.length; i += 1) result.push(items.slice(i, i + n).join(" "));
    }
    return result;
  }

  function setModel(value) {
    if (!value || typeof value.intercept !== "number" || !value.vocab || !value.ngram_max) {
      throw new Error("Invalid browser model artifact");
    }
    model = value;
    return model;
  }

  async function loadModel(url) {
    const response = await fetch(url, {cache: "force-cache"});
    if (!response.ok) throw new Error(`Could not load browser model (${response.status})`);
    return setModel(await response.json());
  }

  function scoreTfidf(text) {
    if (!model) throw new Error("The browser model is still loading");
    const counts = new Map();
    for (const gram of ngrams(tokens(text), model.ngram_max)) {
      if (model.vocab[gram]) counts.set(gram, (counts.get(gram) || 0) + 1);
    }
    let norm = 0;
    const vector = [];
    for (const [term, count] of counts) {
      const [idf, coefficient] = model.vocab[term];
      const tf = model.sublinear_tf ? 1 + Math.log(count) : count;
      const value = tf * idf;
      vector.push([value, coefficient]);
      norm += value * value;
    }
    norm = Math.sqrt(norm) || 1;
    let logit = model.intercept;
    for (const [value, coefficient] of vector) logit += (value / norm) * coefficient;
    return sigmoid(logit);
  }

  function tfidfSignals(text, topK = 6) {
    if (!model) throw new Error("The browser model is still loading");
    const weighted = [];
    for (const term of new Set(tokens(text))) {
      const entry = model.vocab[term];
      if (entry && entry[1] > 0 && !term.includes(" ")) weighted.push([term, entry[1]]);
    }
    return weighted.sort((a, b) => b[1] - a[1]).slice(0, topK).map((entry) => entry[0]);
  }

  function scoreHeuristic(text) {
    let logit = H_BIAS;
    for (const [pattern, weight] of H_SIGNALS) if (pattern.test(text)) logit += weight;
    return sigmoid(logit);
  }

  function heuristicSignals(text) {
    return H_SIGNALS.filter(([pattern]) => pattern.test(text)).map(([, , name]) => name);
  }

  function validateText(text) {
    if (typeof text !== "string" || text.length === 0) throw new Error("Message text is required");
    if (text.length > MAX_TEXT) throw new Error(`Message exceeds the ${MAX_TEXT.toLocaleString()} character limit`);
  }

  function rawScore(text, detector) {
    if (detector === "heuristic-v0") return {probability: scoreHeuristic(text), signals: heuristicSignals(text)};
    if (detector === "tfidf-logreg") return {probability: scoreTfidf(text), signals: tfidfSignals(text)};
    throw new Error(`Browser edition does not include detector: ${detector}`);
  }

  function scoreMessage(text, detector = "tfidf-logreg", threshold = THRESHOLD) {
    validateText(text);
    const scored = rawScore(text, detector);
    return {
      text,
      detector,
      fraud_probability: scored.probability,
      label: scored.probability >= threshold ? "fraud" : "benign",
      threshold,
      signals: scored.signals,
      policy_id: null,
      threshold_source: "browser-default",
    };
  }

  function applyRate(text, mapping, rate) {
    const step = rate > 0 ? Math.max(1, Math.round(1 / rate)) : 0;
    if (!step) return text;
    let seen = 0;
    let result = "";
    for (const character of text) {
      if (mapping[character] !== undefined) {
        seen += 1;
        result += seen % step === 0 ? mapping[character] : character;
      } else result += character;
    }
    return result;
  }

  function attackText(text, attack) {
    if (attack === "homoglyph") return applyRate(text, HOMOGLYPHS, 0.5);
    if (attack === "leet") return applyRate(text, LEET, 0.5);
    if (attack === "zero-width") {
      const step = Math.max(1, Math.round(1 / 0.34));
      let seen = 0;
      let result = "";
      for (const character of text) {
        result += character;
        if (/[a-z0-9]/i.test(character)) {
          seen += 1;
          if (seen % step === 0) result += ZERO_WIDTH;
        }
      }
      return result;
    }
    if (attack === "whitespace") {
      return text.split(" ").map((item) => {
        if (/^[a-zA-Z]+$/.test(item) && item.length >= 5) {
          const middle = Math.floor(item.length / 2);
          return `${item.slice(0, middle)} ${item.slice(middle)}`;
        }
        return item;
      }).join(" ");
    }
    throw new Error(`Browser edition does not include attack: ${attack}`);
  }

  function isAlpha(character) {
    return character !== undefined && /\p{L}/u.test(character);
  }

  function normalize(text) {
    let result = text.replace(/\p{Cf}/gu, "").normalize("NFKC");
    result = Array.from(result, (character) => CONFUSABLES[character] || character).join("");
    const characters = Array.from(result);
    for (let i = 0; i < characters.length; i += 1) {
      const replacement = DELEET[characters[i]];
      if (replacement !== undefined && (isAlpha(characters[i - 1]) || isAlpha(characters[i + 1]))) {
        characters[i] = replacement;
      }
    }
    return characters.join("");
  }

  function attackMessage(text, attack, detector = "tfidf-logreg", defense = "none", threshold = THRESHOLD) {
    validateText(text);
    const attacked = attackText(text, attack);
    const clean = scoreMessage(text, detector, threshold);
    const attackedScore = scoreMessage(attacked, detector, threshold);
    const cleanFlagged = clean.fraud_probability >= threshold;
    const attackedFlagged = attackedScore.fraud_probability >= threshold;
    const evaded = cleanFlagged && !attackedFlagged;
    const defendedText = defense === "normalize" ? normalize(attacked) : null;
    const defended = defendedText === null ? null : scoreMessage(defendedText, detector, threshold);
    const defendedFlagged = defended ? defended.fraud_probability >= threshold : null;
    return {
      detector,
      attack,
      original: text,
      attacked,
      clean_probability: clean.fraud_probability,
      attacked_probability: attackedScore.fraud_probability,
      threshold,
      clean_flagged: cleanFlagged,
      attacked_flagged: attackedFlagged,
      evaded,
      defense,
      defended_text: defendedText,
      defended_probability: defended ? defended.fraud_probability : null,
      defended_flagged: defendedFlagged,
      defense_recovered: defended ? evaded && defendedFlagged : null,
      defended_evaded: defended ? cleanFlagged && !defendedFlagged : null,
    };
  }

  function parseHeaders(block) {
    const unfolded = block.replace(/\r?\n[ \t]+/g, " ");
    const headers = new Map();
    for (const line of unfolded.split(/\r?\n/)) {
      const separator = line.indexOf(":");
      if (separator < 1) continue;
      const name = line.slice(0, separator).trim().toLowerCase();
      const value = line.slice(separator + 1).trim();
      if (!headers.has(name)) headers.set(name, []);
      headers.get(name).push(value);
    }
    return headers;
  }

  function headerValues(headers, name) {
    return headers.get(name.toLowerCase()) || [];
  }

  function firstHeader(headers, name) {
    return headerValues(headers, name)[0] || "";
  }

  function splitMessage(raw) {
    const match = /\r?\n\r?\n/.exec(raw);
    if (!match) return {headers: parseHeaders(raw), body: ""};
    return {
      headers: parseHeaders(raw.slice(0, match.index)),
      body: raw.slice(match.index + match[0].length),
    };
  }

  function base64Text(value) {
    const compact = value.replace(/\s/g, "");
    let bytes;
    if (typeof Buffer !== "undefined") bytes = Uint8Array.from(Buffer.from(compact, "base64"));
    else bytes = Uint8Array.from(atob(compact), (character) => character.charCodeAt(0));
    return new TextDecoder("utf-8", {fatal: false}).decode(bytes);
  }

  function quotedPrintableText(value) {
    const unfolded = value.replace(/=\r?\n/g, "");
    const bytes = [];
    for (let i = 0; i < unfolded.length; i += 1) {
      if (unfolded[i] === "=" && /^[0-9a-f]{2}$/i.test(unfolded.slice(i + 1, i + 3))) {
        bytes.push(parseInt(unfolded.slice(i + 1, i + 3), 16));
        i += 2;
      } else {
        bytes.push(...new TextEncoder().encode(unfolded[i]));
      }
    }
    return new TextDecoder("utf-8", {fatal: false}).decode(Uint8Array.from(bytes));
  }

  function decodeTransfer(body, encoding) {
    try {
      if (/\bbase64\b/i.test(encoding)) return base64Text(body);
      if (/quoted-printable/i.test(encoding)) return quotedPrintableText(body);
    } catch (_) {
      return body;
    }
    return body;
  }

  function decodeEncodedWords(value) {
    return value.replace(/=\?utf-8\?([bq])\?([^?]+)\?=/gi, (_, kind, payload) => {
      try {
        return kind.toLowerCase() === "b" ? base64Text(payload) : quotedPrintableText(payload.replace(/_/g, " "));
      } catch (_) {
        return payload;
      }
    });
  }

  function stripHtml(value) {
    const withoutActive = value.replace(/<(script|style|head)\b[^>]*>[\s\S]*?<\/\1>/gi, " ");
    return withoutActive
      .replace(/<(br|p|div|li|tr)\b[^>]*>/gi, "\n")
      .replace(/<[^>]+>/g, " ")
      .replace(/&nbsp;/gi, " ")
      .replace(/&amp;/gi, "&")
      .replace(/&lt;/gi, "<")
      .replace(/&gt;/gi, ">")
      .replace(/&#39;/gi, "'")
      .replace(/&quot;/gi, '"')
      .replace(/[ \t]+/g, " ")
      .replace(/\n{3,}/g, "\n\n")
      .trim();
  }

  function parameter(value, name) {
    const pattern = new RegExp(`${name}\\s*=\\s*(?:"([^"]+)"|([^;\\s]+))`, "i");
    const match = pattern.exec(value);
    return match ? decodeEncodedWords(match[1] || match[2]) : null;
  }

  function parseMimeBody(headers, body) {
    const contentType = firstHeader(headers, "content-type") || "text/plain";
    const boundary = parameter(contentType, "boundary");
    const plain = [];
    const html = [];
    const attachments = [];
    const hrefs = [];

    function consume(partHeaders, partBody) {
      const partType = firstHeader(partHeaders, "content-type") || "text/plain";
      const disposition = firstHeader(partHeaders, "content-disposition");
      const filename = parameter(disposition, "filename") || parameter(partType, "name");
      if (filename) attachments.push(filename);
      if (/\battachment\b/i.test(disposition)) return;
      const decoded = decodeTransfer(partBody, firstHeader(partHeaders, "content-transfer-encoding"));
      if (/^text\/plain\b/i.test(partType)) plain.push(decoded.trim());
      if (/^text\/html\b/i.test(partType)) {
        html.push(stripHtml(decoded));
        for (const match of decoded.matchAll(/\bhref\s*=\s*["'](https?:\/\/[^"']+)["']/gi)) hrefs.push(match[1]);
      }
    }

    if (/^multipart\//i.test(contentType) && boundary) {
      const marker = `--${boundary}`;
      for (const rawPart of body.split(marker).slice(1)) {
        if (rawPart.startsWith("--")) break;
        const part = splitMessage(rawPart.replace(/^\r?\n/, "").replace(/\r?\n$/, ""));
        consume(part.headers, part.body);
      }
    } else consume(headers, body);

    const selected = plain.some((item) => item) ? plain : html;
    return {body: selected.filter(Boolean).join("\n\n").trim(), attachments, hrefs};
  }

  function parseAddress(value) {
    const angle = /<([^<>\s]+@[^<>\s]+)>/.exec(value);
    const bare = /[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+/i.exec(value);
    return (angle ? angle[1] : bare ? bare[0] : "").toLowerCase() || null;
  }

  function addressDomain(address) {
    return address && address.includes("@") ? address.slice(address.lastIndexOf("@") + 1).replace(/>$/, "").toLowerCase() : null;
  }

  function filenameSuffix(filename) {
    const name = filename.toLowerCase();
    const index = name.lastIndexOf(".");
    return index < 0 ? "" : name.slice(index);
  }

  function isIpLiteral(hostname) {
    const host = hostname.replace(/^\[|\]$/g, "");
    if (host.includes(":")) return /^[0-9a-f:]+$/i.test(host);
    const parts = host.split(".");
    return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
  }

  function emailEvidence(parsed) {
    const evidence = [];
    const fromDomain = addressDomain(parsed.from_address);
    const replyDomain = addressDomain(parsed.reply_to);
    if (fromDomain && replyDomain && fromDomain !== replyDomain) {
      evidence.push({code:"reply_to_domain_mismatch", severity:"medium", title:"Reply-To domain differs", detail:`From uses ${fromDomain}; replies go to ${replyDomain}.`});
    }
    const domains = new Set();
    for (const url of parsed.urls) {
      try { domains.add(new URL(url).hostname); } catch (_) { /* Ignore malformed display URLs. */ }
    }
    for (const domain of Array.from(domains).sort()) {
      const normalized = domain.toLowerCase();
      if (normalized.startsWith("xn--") || normalized.includes(".xn--")) {
        evidence.push({code:"punycode_url", severity:"medium", title:"Punycode link domain", detail:`The message contains an internationalized domain encoding: ${domain}.`});
      }
      if (isIpLiteral(normalized)) {
        evidence.push({code:"ip_literal_url", severity:"medium", title:"Link uses an IP address", detail:`The message links directly to ${domain} instead of a named domain.`});
      }
    }
    const authentication = parsed.authentication_results.join(" ").toLowerCase();
    const failed = ["spf", "dkim", "dmarc"].filter((name) => new RegExp(`\\b${name}=fail\\b`).test(authentication)).sort();
    if (failed.length) {
      evidence.push({code:"email_authentication_failed", severity:"medium", title:"Header reports email authentication failure", detail:`Authentication-Results reports failure for ${failed.join(", ")}; verify that the header came from a trusted gateway.`});
    }
    for (const filename of parsed.attachments) {
      const suffix = filenameSuffix(filename);
      if (DANGEROUS_EXTENSIONS.has(suffix)) evidence.push({code:"executable_attachment", severity:"high", title:"Executable attachment", detail:`Attachment '${filename}' has a high-risk executable extension.`});
      else if (ARCHIVE_EXTENSIONS.has(suffix)) evidence.push({code:"archive_attachment", severity:"medium", title:"Archive or disk-image attachment", detail:`Attachment '${filename}' requires controlled inspection.`});
    }
    return evidence;
  }

  function byteLength(value) {
    return new TextEncoder().encode(value).length;
  }

  function triageEmail(raw, detector = "tfidf-logreg", threshold = THRESHOLD) {
    if (typeof raw !== "string" || !raw) throw new Error("Email source is required");
    if (byteLength(raw) > MAX_EMAIL_BYTES) throw new Error("Email exceeds the 5 MB safety limit");
    const message = splitMessage(raw);
    const mime = parseMimeBody(message.headers, message.body);
    const subject = decodeEncodedWords(firstHeader(message.headers, "subject")).trim();
    const scoreText = [subject, mime.body].filter(Boolean).join("\n\n").trim();
    if (!scoreText) throw new Error("Email has no subject or readable text body");
    const urls = Array.from(new Set([...(mime.body.match(URL_RE) || []), ...mime.hrefs].map((item) => item.replace(/[.,);\]]+$/, "")))).sort();
    const parsed = {
      subject,
      from_address: parseAddress(firstHeader(message.headers, "from")),
      reply_to: parseAddress(firstHeader(message.headers, "reply-to")),
      recipients: headerValues(message.headers, "to").concat(headerValues(message.headers, "cc")).map(parseAddress).filter(Boolean),
      message_id: firstHeader(message.headers, "message-id") || null,
      body: mime.body,
      urls,
      attachments: Array.from(new Set(mime.attachments)),
      authentication_results: headerValues(message.headers, "authentication-results"),
    };
    const scored = scoreMessage(scoreText.slice(0, MAX_TEXT), detector, threshold);
    const evidence = emailEvidence(parsed);
    const severities = new Set(evidence.map((item) => item.severity));
    let riskTier;
    let action;
    if (scored.label === "fraud" || severities.has("high")) {
      riskTier = "high";
      action = "Quarantine and send for analyst review; do not open links or attachments.";
    } else if (evidence.length || scored.fraud_probability >= scored.threshold * 0.6) {
      riskTier = "review";
      action = "Hold for review and verify the sender through a trusted channel.";
    } else {
      riskTier = "low";
      action = "No strong signal found; continue normal email-security controls.";
    }
    return {
      schema_version: 1,
      browser_preview: true,
      risk_tier: riskTier,
      recommended_action: action,
      detector,
      content_probability: scored.fraud_probability,
      content_label: scored.label,
      threshold,
      threshold_source: "browser-default",
      policy_id: null,
      subject: parsed.subject,
      from_address: parsed.from_address,
      reply_to: parsed.reply_to,
      recipients: parsed.recipients,
      message_id: parsed.message_id,
      signals: scored.signals,
      evidence,
      urls: parsed.urls,
      attachments: parsed.attachments,
    };
  }

  function capabilities() {
    return {
      detectors: ["tfidf-logreg", "heuristic-v0"],
      attacks: ["homoglyph", "leet", "zero-width", "whitespace"],
      defenses: ["none", "normalize"],
      default_detector: "tfidf-logreg",
    };
  }

  return {
    THRESHOLD,
    MAX_TEXT,
    MAX_EMAIL_BYTES,
    setModel,
    loadModel,
    capabilities,
    scoreMessage,
    attackText,
    normalize,
    attackMessage,
    triageEmail,
  };
}));
