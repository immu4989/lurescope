const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const {plan} = require('../lurescope/static/capacity-planner.js');

// A deliberately small DOM double tests the form adapter, not browser layout.
function mount() {
  const nodes = new Map();
  function element() {
    return {value: '', textContent: '', hidden: false, disabled: false, children: [],
      listeners: {}, addEventListener(event, fn) { this.listeners[event] = fn; },
      appendChild(child) { this.children.push(child); },
      replaceChildren() { this.children = []; }};
  }
  const defaults = {capacityDetector: 'synthetic-example', capacityThreshold: '.5',
    capacity_tp: '96', capacity_fn: '4', capacity_fp: '2', capacity_tn: '98',
    capacity_abstained_positive: '0', capacity_abstained_negative: '0',
    capacityVolume: '1000000', capacityMinutes: '5', capacityHours: '1000',
    capacityLow: '.1', capacityMiddle: '1', capacityHigh: '5'};
  for (const id of ['capacityForm', 'capacityResult', 'capacityError', 'capacityDownload',
    'capacitySource', 'capacityRows', ...Object.keys(defaults)]) {
    nodes.set(id, Object.assign(element(), {value: defaults[id] || ''}));
  }
  const context = vm.createContext({Intl, LureScopeCapacity: {plan}, document: {
    getElementById(id) { assert.ok(nodes.has(id), `unknown element ${id}`); return nodes.get(id); },
    createElement: element,
  }});
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../lurescope/static/capacity-ui.js'), 'utf8'), context);
  return {get: id => nodes.get(id), edit(id, value) {
    nodes.get(id).value = value;
    nodes.get('capacityForm').listeners.input();
  }, submit() { nodes.get('capacityForm').listeners.submit({preventDefault() {}}); }};
}

test('initial synthetic scenario renders and input changes invalidate downloads', () => {
  const ui = mount();
  assert.equal(ui.get('capacityResult').hidden, false);
  assert.equal(ui.get('capacityRows').children.length, 3);
  assert.equal(ui.get('capacityDownload').disabled, false);
  ui.edit('capacityHours', '2000');
  assert.equal(ui.get('capacityResult').hidden, true);
  assert.equal(ui.get('capacityDownload').disabled, true);
  assert.match(ui.get('capacitySource').textContent, /not independently verified/);
  ui.submit();
  assert.equal(ui.get('capacityResult').hidden, false);
  assert.equal(ui.get('capacityRows').children[0].children[4].textContent, 'Within supplied hours');
});

test('empty counts and duplicate prevalence never retain valid old output', () => {
  const ui = mount();
  ui.edit('capacity_tp', '');
  ui.submit();
  assert.equal(ui.get('capacityResult').hidden, true);
  assert.equal(ui.get('capacityDownload').disabled, true);
  assert.match(ui.get('capacityError').textContent, /required/);
  ui.edit('capacity_tp', '96');
  ui.edit('capacityLow', '1');
  ui.submit();
  assert.equal(ui.get('capacityResult').hidden, true);
  assert.equal(ui.get('capacityDownload').disabled, true);
});

test('rare nonzero prevalence is not rounded to zero in displayed scenarios', () => {
  const ui = mount();
  ui.edit('capacityLow', '.000001');
  ui.submit();
  const formatted = new Intl.NumberFormat(undefined, {maximumSignificantDigits: 6}).format(.000001);
  assert.equal(ui.get('capacityRows').children[0].children[0].textContent, formatted + '%');
});
