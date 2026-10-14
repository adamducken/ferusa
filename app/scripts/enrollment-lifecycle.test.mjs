import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import ts from "typescript";

const page = await readFile(new URL("../src/routes/+page.svelte", import.meta.url), "utf8");
const setup = await readFile(new URL("../src/lib/components/Setup.svelte", import.meta.url), "utf8");

function script(source, globals, expose) {
  const body = source.match(/<script lang="ts">([\s\S]*?)<\/script>/)[1]
    .replace(/^\s*import [\s\S]*?;/gm, "");
  const js = ts.transpile(body, { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None });
  return new Function(...Object.keys(globals), `${js}\nreturn { ${expose} };`)(...Object.values(globals));
}

const flush = async () => { for (let i = 0; i < 20; i++) await Promise.resolve(); };
const deferred = () => {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
};

function mount(paired = false, pending = false) {
  const document = { visibilityState: "visible" };
  const events = new Map();
  let onMount;
  const backend = {
    setup_status: () => ({ paired, pending }),
    set_app_foreground: () => {},
    pending_request: () => null,
    pending_recovery: () => null,
  };
  const state = script(page, {
    $state: (value) => value,
    document,
    window: { setTimeout() {}, clearTimeout() {}, setInterval() {}, clearInterval() {} },
    onMount: (callback) => { onMount = callback; },
    listen: async (event, callback) => { events.set(event, callback); return () => {}; },
    invoke: async (command) => backend[command](),
    formatInvokeError: String,
  }, "syncForegroundState, refreshSetup, onSetupComplete, onUnlocked, onReplacementAuthorized, handleRecovery, reconcilePendingRecovery, onRecoveryDenied, onRecoveryResultDone, get screen() { return screen; }, get unlocked() { return isUnlocked; }, get enrollment() { return enrollmentActive; }, get recovery() { return pendingRecovery; }");
  onMount();
  return { state, document, events, backend };
}

test("every initial enrollment step stays mounted through hide, expiry, and resume", async () => {
  const { state, document, events } = mount();
  await flush();
  const enrollment = script(setup, {
    $state: (value) => value,
    $props: () => ({ oncomplete() {} }),
    onMount() {},
    onDestroy() {},
  }, "setStep(value) { step = value; }, get step() { return step; }");
  for (const step of ["node-id", "pin4", "pin4-confirm", "pin6", "pin6-confirm", "verify-code", "pairing"]) {
    enrollment.setStep(step);
    document.visibilityState = "hidden";
    const hidden = state.syncForegroundState();
    assert.equal(state.screen, "setup", step);
    assert.equal(state.unlocked, false);
    events.get("ferusa://session-expired")();
    await hidden;
    await flush();
    assert.equal(state.screen, "setup", step);
    document.visibilityState = "visible";
    await state.syncForegroundState();
    assert.equal(state.screen, "setup", step);
    assert.equal(enrollment.step, step);
  }
});

test("paired app locks before background IPC finishes and resumes at biometrics", async () => {
  const { state, document, backend } = mount(true);
  await flush();
  state.onUnlocked();
  assert.equal(state.screen, "idle");
  const pending = deferred();
  backend.set_app_foreground = () => pending.promise;
  document.visibilityState = "hidden";
  const hidden = state.syncForegroundState();
  assert.equal(state.unlocked, false);
  assert.equal(state.screen, "biometric");
  state.onUnlocked();
  assert.equal(state.unlocked, false);
  pending.resolve();
  await hidden;
  document.visibilityState = "visible";
  await state.syncForegroundState();
  assert.equal(state.screen, "biometric");
});

test("stale setup checks cannot undo pairing completion or unlock", async () => {
  const { state, backend } = mount();
  await flush();
  const old = deferred();
  backend.setup_status = () => old.promise;
  const refresh = state.refreshSetup();
  state.onSetupComplete();
  state.onUnlocked();
  old.resolve({ paired: false, pending: false });
  await refresh;
  assert.equal(state.screen, "idle");
  assert.equal(state.unlocked, true);
});

test("setup-changed rechecks storage and returns an unpaired app to enrollment", async () => {
  const { state, backend, events } = mount(true);
  await flush();
  backend.setup_status = () => ({ paired: false, pending: false });
  events.get("ferusa://setup-changed")();
  await flush();
  assert.equal(state.screen, "setup");
  assert.equal(state.unlocked, false);
});

const recovery = (instance_id, phase = "review") => ({
  request_id: instance_id,
  instance_id,
  purpose: "initial_setup",
  correlation_code: 1234,
  pairing_id: "pending-pairing",
  remaining_ms: 60_000,
  phase,
});

test("candidate recovery overlays mounted setup before setup completion", async () => {
  const { state } = mount();
  await flush();
  state.handleRecovery(recovery("A"));
  assert.equal(state.screen, "recovery");
  assert.equal(state.enrollment, true);
  await state.refreshSetup();
  assert.equal(state.screen, "recovery");
  state.handleRecovery(recovery("A", "confirmed"));
  assert.equal(state.screen, "recovery_result");
  assert.equal(state.enrollment, true);
  state.onRecoveryResultDone();
  assert.equal(state.screen, "setup");
  state.onSetupComplete();
  assert.equal(state.enrollment, false);
  assert.equal(state.screen, "biometric");
  assert.match(page, /\{#if enrollmentActive\}[\s\S]*?<div hidden=\{screen !== "setup"\}>[\s\S]*?<Setup/);
});

test("pending candidate keeps enrollment routing through lock and foreground", async () => {
  for (const paired of [false, true]) {
    const { state, document, events } = mount(paired, true);
    await flush();
    assert.equal(state.screen, "setup");
    state.onUnlocked();
    assert.equal(state.unlocked, false);
    state.handleRecovery(recovery("A"));
    assert.equal(state.screen, "recovery");
    document.visibilityState = "hidden";
    await state.syncForegroundState();
    events.get("ferusa://session-expired")();
    await flush();
    assert.equal(state.screen, "setup");
    assert.equal(state.enrollment, true);
    assert.equal(state.recovery, null);
    document.visibilityState = "visible";
    await state.syncForegroundState();
    assert.equal(state.screen, "setup");
  }
});

test("stale recovery getter and terminal callbacks cannot replace a newer request", async () => {
  const { state, backend } = mount();
  await flush();
  state.handleRecovery(recovery("A"));
  const getter = deferred();
  backend.pending_recovery = () => getter.promise;
  const queried = state.reconcilePendingRecovery();
  state.handleRecovery(recovery("B"));
  getter.resolve(recovery("A", "review"));
  await queried;
  state.handleRecovery(recovery("A", "confirmed"));
  state.onRecoveryDenied("A");
  assert.equal(state.recovery.instance_id, "B");
  assert.equal(state.screen, "recovery");
});

test("same-instance phase events cannot be undone by an older getter", async () => {
  const { state, backend } = mount();
  await flush();
  state.handleRecovery(recovery("A"));
  const getter = deferred();
  backend.pending_recovery = () => getter.promise;
  const queried = state.reconcilePendingRecovery();
  state.handleRecovery(recovery("A", "waiting_for_laptop"));
  getter.resolve(recovery("A"));
  await queried;
  assert.equal(state.recovery.phase, "waiting_for_laptop");
});

test("durable initial completion reconciles a callback interrupted by lock", async () => {
  const { state, backend } = mount(false, true);
  await flush();
  backend.setup_status = () => ({ paired: true, pending: true });
  await state.refreshSetup();
  assert.equal(state.screen, "setup");
  assert.equal(state.enrollment, true);
  backend.setup_status = () => ({ paired: true, pending: false });
  await state.refreshSetup();
  assert.equal(state.screen, "biometric");
  assert.equal(state.enrollment, false);
  assert.equal(state.unlocked, false);
});

test("replacement completion clears the old unlocked UI session", async () => {
  const { state } = mount(true);
  await flush();
  state.onUnlocked();
  state.onReplacementAuthorized();
  assert.equal(state.enrollment, true);
  state.onSetupComplete();
  assert.equal(state.enrollment, false);
  assert.equal(state.screen, "biometric");
  assert.equal(state.unlocked, false);
});
