<script lang="ts">
  import { onDestroy, onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import {
    Format,
    checkPermissions,
    requestPermissions,
    scan,
  } from "@tauri-apps/plugin-barcode-scanner";
  import { Check } from "lucide-svelte";
  import { formatInvokeError } from "$lib/errors";
  import SecurityFrame from "./SecurityFrame.svelte";

  let {
    oncomplete,
    oncancel,
    mode = "initial",
  }: {
    oncomplete: () => void;
    oncancel?: () => void;
    mode?: "initial" | "replacement";
  } = $props();

  type Step =
    | "node-id"
    | "pin4"
    | "pin4-confirm"
    | "pin6"
    | "pin6-confirm"
    | "verify-code"
    | "pairing";

  let step = $state<Step>("node-id");
  let cliNodeId = $state("");
  let pin4 = $state("");
  let pin4Confirm = $state("");
  let pin6 = $state("");
  let pin6Confirm = $state("");
  let pairingCode = $state("");
  let error = $state("");
  let loading = $state(false);

  let scanning = $state(false);
  let scanError = $state("");
  let resuming = $state(false);
  let operationRevision = 0;
  let disposed = false;

  onDestroy(() => {
    disposed = true;
    operationRevision += 1;
    clearPins();
  });

  function isCurrent(revision: number) {
    return !disposed && operationRevision === revision;
  }

  function clearPins() {
    pin4 = "";
    pin4Confirm = "";
    pin6 = "";
    pin6Confirm = "";
  }

  function isEnrollmentToken(value: string) {
    if (value.length > 2048 || new TextEncoder().encode(value).length > 2048) return false;
    try {
      const token = JSON.parse(value);
      return token !== null && typeof token === "object" && token.version === 5;
    } catch {
      return false;
    }
  }

  // Step number for progress bar (pairing is still step 3 visually)
  const stepNumber: Record<Step, number> = {
    "node-id": 1,
    pin4: 2,
    "pin4-confirm": 2,
    pin6: 3,
    "pin6-confirm": 3,
    "verify-code": 4,
    pairing: 4,
  };
  const totalSteps = 4;

  onMount(async () => {
    try {
      const perm = await checkPermissions();
      if (
        String(perm) === "prompt" ||
        String(perm) === "prompt-with-rationale"
      ) {
        await requestPermissions();
      }
    } catch (_) {}
  });

  // ── QR scanning ──────────────────────────────────────────────────────────────

  async function startScan() {
    if (scanning || loading) return;
    const revision = ++operationRevision;
    scanError = "";
    scanning = true;
    try {
      let perm = await checkPermissions();
      if (!isCurrent(revision)) return;
      if (String(perm) !== "granted") {
        const req = await requestPermissions();
        if (!isCurrent(revision)) return;
        if (String(req) !== "granted") {
          scanError =
            "Camera permission denied. Go to Settings → Apps → ferusa → Permissions.";
          return;
        }
      }
      const result = await scan({ formats: [Format.QRCode], windowed: false });
      if (!isCurrent(revision)) return;
      const content = result.content?.trim() ?? "";
      if (isEnrollmentToken(content)) {
        cliNodeId = content;
        error = "";
        scanError = "";
      } else {
        scanError =
          "Scan the complete Ferusa enrollment token from the desktop. A node ID alone cannot resume setup.";
      }
    } catch (e: any) {
      const msg = String(e);
      if (isCurrent(revision) && !msg.toLowerCase().includes("cancel")) {
        scanError = `Scan failed: ${msg}`;
      }
    } finally {
      if (isCurrent(revision)) scanning = false;
    }
  }

  // ── Step navigation ───────────────────────────────────────────────────────────

  async function onNodeIdSubmit() {
    if (loading || scanning) return;
    const trimmed = cliNodeId.trim();
    if (!isEnrollmentToken(trimmed)) {
      error = "Paste the complete version 5 enrollment token from the desktop, including its transaction details.";
      return;
    }
    const revision = ++operationRevision;
    loading = true;
    error = "";
    try {
      const enrollment = await invoke<{ resume: boolean }>("setup_enrollment", {
        enrollmentToken: trimmed,
      });
      if (!isCurrent(revision)) return;
      cliNodeId = trimmed;
      resuming = enrollment.resume;
      clearPins();
      loading = false;
      if (resuming) {
        await showPairingVerification();
      } else {
        step = "pin4";
        focusPinInput("pin4");
      }
    } catch (cause) {
      if (isCurrent(revision)) error = formatInvokeError(cause);
    } finally {
      if (isCurrent(revision)) loading = false;
    }
  }

  function onPin4Submit() {
    if (!/^\d{4}$/.test(pin4)) {
      error = "4-digit PIN required (digits only).";
      return;
    }
    if (isTrivialPin(pin4)) {
      error = "Choose a PIN that is not common, repeated, or sequential.";
      return;
    }
    error = "";
    step = "pin4-confirm";
    focusPinInput("pin4-confirm");
  }

  function onPin4ConfirmSubmit() {
    if (pin4Confirm !== pin4) {
      error = "PINs do not match.";
      pin4Confirm = "";
      return;
    }
    error = "";
    step = "pin6";
    focusPinInput("pin6");
  }

  function onPin6Submit() {
    if (!/^\d{6}$/.test(pin6)) {
      error = "6-digit PIN required (digits only).";
      return;
    }
    if (isTrivialPin(pin6)) {
      error = "Choose a PIN that is not common, repeated, or sequential.";
      return;
    }
    error = "";
    step = "pin6-confirm";
    focusPinInput("pin6-confirm");
  }

  function focusPinInput(target: Step) {
    setTimeout(() => {
      document
        .querySelector<HTMLInputElement>(`[data-pin-input="${target}"]`)
        ?.focus();
    }, 50);
  }

  function isTrivialPin(pin: string): boolean {
    const repeated = /^(\d)\1+$/.test(pin);
    const ascending = "0123456789".includes(pin);
    const descending = "9876543210".includes(pin);
    const common = ["1212", "1122", "2580", "121212", "112233", "258025"].includes(pin);
    return repeated || ascending || descending || common;
  }

  function onPin6ConfirmSubmit() {
    if (pin6Confirm !== pin6) {
      error = "PINs do not match.";
      pin6Confirm = "";
      return;
    }
    error = "";
    showPairingVerification();
  }

  async function showPairingVerification() {
    const revision = ++operationRevision;
    loading = true;
    try {
      const code = await invoke<string>("setup_pairing_code");
      if (!isCurrent(revision)) return;
      pairingCode = code;
      error = "";
      step = "verify-code";
    } catch (e: any) {
      if (isCurrent(revision)) error = formatInvokeError(e);
    } finally {
      if (isCurrent(revision)) loading = false;
    }
  }

  function onPairingCodeConfirmed() {
    if (!loading) void finishSetup();
  }

  async function finishSetup() {
    const revision = ++operationRevision;
    loading = true;
    step = "pairing";
    const payload = {
      pin4: resuming ? "" : pin4,
      pin6: resuming ? "" : pin6,
      cli_node_id_hex: cliNodeId,
    };
    clearPins();
    try {
      await invoke("setup_complete", { payload });
      if (isCurrent(revision)) oncomplete();
    } catch (e: any) {
      if (isCurrent(revision)) {
        error = `${formatInvokeError(e)} Resume with the same enrollment token; keep the desktop transaction and recovery file.`;
        step = "node-id";
        loading = false;
      }
    } finally {
      payload.pin4 = "";
      payload.pin6 = "";
    }
  }

  function onVisibilityChange() {
    if (document.visibilityState === "visible" || !loading) return;
    operationRevision += 1;
    clearPins();
    loading = false;
    step = "node-id";
    error = "Setup paused. Resume with the same enrollment token and approve again.";
  }

  function setPin4(value: string) {
    pin4 = value.replace(/\D/g, "");

    if (pin4.length === 4 && step === "pin4" && !loading) {
      onPin4Submit();
    }
  }

  function setPin4Confirm(value: string) {
    pin4Confirm = value.replace(/\D/g, "");

    if (pin4Confirm.length === 4 && step === "pin4-confirm" && !loading) {
      onPin4ConfirmSubmit();
    }
  }

  function setPin6(value: string) {
    pin6 = value.replace(/\D/g, "");

    if (pin6.length === 6 && step === "pin6" && !loading) {
      onPin6Submit();
    }
  }

  function setPin6Confirm(value: string) {
    pin6Confirm = value.replace(/\D/g, "");

    if (pin6Confirm.length === 6 && step === "pin6-confirm" && !loading) {
      onPin6ConfirmSubmit();
    }
  }
</script>

<SecurityFrame>
        <!-- ── Progress bar ─────────────────────────────────────────────────── -->
        <div class="progress-header">
          <span class="progress-label">
            {mode === "replacement" ? "Replacement Progress" : "Setup Progress"}
          </span>
          <span class="progress-step"
            >Step {stepNumber[step]} of {totalSteps}</span
          >
        </div>
        <div class="progress-track">
          {#each Array(totalSteps) as _, i (i)}
            <div
              class={[
                "progress-segment",
                { active: i + 1 <= stepNumber[step] },
              ]}
            ></div>
          {/each}
        </div>

        <!-- ── Node ID step ─────────────────────────────────────────────────── -->
        {#if step === "node-id"}
          <div class="title">
            <h1>{mode === "replacement" ? "Replace Pairing" : "Pair Device"}</h1>
            <p>
              Run <code>{mode === "replacement" ? "ferusa pair" : "ferusa init"}</code>
              on your desktop, then scan the complete enrollment token to establish a secure link.
              {#if mode === "replacement"}
                Do not clear the current phone or desktop pairing while this runs.
              {/if}
            </p>
          </div>

          <div class="code-block">
            <span class="code-label">SCAN QR CODE</span>

            <button
              class="btn btn-approve scan-btn"
              onclick={startScan}
              disabled={scanning || loading}
            >
              {#if scanning}
                <span class="spinner-inline"></span>
                Opening camera…
              {:else}
                Scan QR Code
              {/if}
            </button>

            {#if scanError}
              <div class="error-box">{scanError}</div>
            {/if}
          </div>

          <div class="field-group">
            <label class="field-label" for="enrollment-token">ENROLLMENT TOKEN</label>
            <textarea
              id="enrollment-token"
              bind:value={cliNodeId}
              rows="4"
              maxlength="2048"
              disabled={loading || scanning}
              spellcheck="false"
              autocomplete="off"
              placeholder="Paste the complete JSON enrollment token…"
              class="node-textarea"
            ></textarea>
          </div>

          {#if error}
            <div class="error-box">{error}</div>
          {/if}

          <div class="btn-stack">
            <button
              class="btn btn-approve"
              onclick={onNodeIdSubmit}
              disabled={loading || scanning || !cliNodeId.trim()}
            >
              {#if loading}
                <span class="spinner-inline"></span>
                Checking enrollment…
              {:else}
                <Check size={18} />
                Continue
              {/if}
            </button>
            {#if mode === "replacement"}
              <button class="btn btn-cancel" onclick={oncancel} disabled={loading}>
                Cancel Replacement
              </button>
            {/if}
          </div>

          <!-- ── PIN steps ─────────────────────────────────────────────────────── -->
        {:else if step === "pin4" || step === "pin4-confirm" || step === "pin6" || step === "pin6-confirm"}
          {@const requiredLength =
            step === "pin6" || step === "pin6-confirm" ? 6 : 4}
          {@const currentPin =
            step === "pin4"
              ? pin4
              : step === "pin4-confirm"
                ? pin4Confirm
                : step === "pin6"
                  ? pin6
                  : pin6Confirm}

          <div class="title">
            {#if step === "pin4"}
              <h1>Read PIN</h1>
              <p>
                Set a 4-digit PIN.<br />Used to approve <strong>read</strong> requests.
              </p>
            {:else if step === "pin4-confirm"}
              <h1>Confirm PIN</h1>
              <p>Re-enter your 4-digit PIN to confirm.</p>
            {:else if step === "pin6"}
              <h1>Write PIN</h1>
              <p>
                Set a 6-digit PIN.<br />Used to approve
                <strong>create, update & delete</strong> requests.
              </p>
            {:else}
              <h1>Confirm PIN</h1>
              <p>Re-enter your 6-digit PIN to confirm.</p>
            {/if}
          </div>

          <div class="code-block relative-container">
            <label class="code-label" for="setup-pin-input">ENTER SECURITY PIN</label>

            <!-- Hidden input -->
            {#if step === "pin4"}
              <input
                data-pin-input="pin4"
                id="setup-pin-input"
                bind:value={() => pin4, setPin4}
                type="password"
                inputmode="numeric"
                maxlength={4}
                disabled={loading}
                autocomplete="off"
                aria-invalid={Boolean(error)}
                aria-describedby={error ? "setup-pin-status setup-pin-error" : "setup-pin-status"}
                class="hidden-pin-input"
              />
            {:else if step === "pin4-confirm"}
              <input
                data-pin-input="pin4-confirm"
                id="setup-pin-input"
                bind:value={() => pin4Confirm, setPin4Confirm}
                type="password"
                inputmode="numeric"
                maxlength={4}
                disabled={loading}
                autocomplete="off"
                aria-invalid={Boolean(error)}
                aria-describedby={error ? "setup-pin-status setup-pin-error" : "setup-pin-status"}
                class="hidden-pin-input"
              />
            {:else if step === "pin6"}
              <input
                data-pin-input="pin6"
                id="setup-pin-input"
                bind:value={() => pin6, setPin6}
                type="password"
                inputmode="numeric"
                maxlength={6}
                disabled={loading}
                autocomplete="off"
                aria-invalid={Boolean(error)}
                aria-describedby={error ? "setup-pin-status setup-pin-error" : "setup-pin-status"}
                class="hidden-pin-input"
              />
            {:else}
              <input
                data-pin-input="pin6-confirm"
                id="setup-pin-input"
                bind:value={() => pin6Confirm, setPin6Confirm}
                type="password"
                inputmode="numeric"
                maxlength={6}
                disabled={loading}
                autocomplete="off"
                aria-invalid={Boolean(error)}
                aria-describedby={error ? "setup-pin-status setup-pin-error" : "setup-pin-status"}
                class="hidden-pin-input"
              />
            {/if}

            <div class="pin-dots" aria-hidden="true">
              {#each Array(requiredLength) as _, i (i)}
                <div
                  class={[
                    "pin-slot",
                    {
                      filled: currentPin.length > i,
                      active: currentPin.length === i && !loading,
                    },
                  ]}
                >
                  {#if currentPin.length > i}
                    <div class="dot"></div>
                  {/if}
                </div>
              {/each}
            </div>
            <p id="setup-pin-status" class="visually-hidden" aria-live="polite">
              {currentPin.length} of {requiredLength} PIN digits entered.
            </p>
          </div>

          {#if error}
            <div id="setup-pin-error" class="error-box" role="alert">{error}</div>
          {/if}

          <div class="btn-stack">
            <button
              class="btn btn-approve"
              onclick={() => {
                if (step === "pin4") onPin4Submit();
                else if (step === "pin4-confirm") onPin4ConfirmSubmit();
                else if (step === "pin6") onPin6Submit();
                else onPin6ConfirmSubmit();
              }}
              disabled={loading || currentPin.length !== requiredLength}
            >
              {#if loading}
                <span class="spinner-inline"></span>
                Saving…
              {:else}
                <Check size={18} />
                Continue
              {/if}
            </button>
          </div>

          <!-- ── Pairing verification ───────────────────────────────────────────── -->
        {:else if step === "verify-code"}
          <div class="title">
            <h1>{resuming ? "Resume Pairing" : "Verify Pairing"}</h1>
            <p>
              Confirm this code matches the one shown on your desktop before
              pairing.
              {#if resuming}
                Your staged phone share and PINs will be reused. Authenticate
                locally, then approve a new recovery request.
              {/if}
            </p>
          </div>

          <div class="code-block">
            <span class="code-label">PAIRING CODE</span>
            <div class="code-value">{pairingCode}</div>
          </div>

          {#if error}
            <div class="error-box">{error}</div>
          {/if}

          <div class="btn-stack">
            <button
              class="btn btn-approve"
              onclick={onPairingCodeConfirmed}
              disabled={loading}
            >
              {#if loading}
                <span class="spinner-inline"></span>
                Pairing…
              {:else}
                <Check size={18} />
                {resuming ? "Resume Pairing" : "Start Pairing"}
              {/if}
            </button>
          </div>

          <!-- ── Pairing spinner ───────────────────────────────────────────────── -->
        {:else if step === "pairing"}
          <div class="title">
            <h1>Pairing</h1>
            <p>Confirm this code on your desktop, then approve the recovery request here.</p>
          </div>

          <div class="code-block pairing-block">
            <span class="code-label">PAIRING CODE</span>
            <div class="code-value">{pairingCode}</div>
            <span class="spinner-large"></span>
            <span class="code-label">ESTABLISHING SECURE LINK</span>
          </div>
          <div class="title">
            <p>Recovery uses your master password and both phone PINs. No new password.</p>
            <p>Keep this recovery drive in a secure location, separate from your phone, laptop, and any vault backups. Do not carry it around with your phone.</p>
            <p>This drive restores access, not your vault data. If you lose the vault and have no separate copy, recovery cannot restore your passwords.</p>
          </div>

          {#if error}
            <div class="error-box">{error}</div>
          {/if}
        {/if}
</SecurityFrame>

<svelte:document onvisibilitychange={onVisibilityChange} />

<style>
  .scan-btn {
    width: auto;
    padding: 14px 32px;
    font-size: 15px;
  }

  .field-group {
    width: 100%;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .field-label {
    padding: 0 2px;
  }

  .node-textarea {
    width: 100%;
    box-sizing: border-box;
    background: #faf9f4;
    border: 1.5px solid #e0d9d0;
    border-radius: 16px;
    color: #1b1c19;
    font-family: monospace;
    font-size: 12px;
    line-height: 1.6;
    padding: 14px 16px;
    resize: none;
    outline: none;
    transition: border-color 0.15s;
  }

  .node-textarea::placeholder {
    color: rgba(86, 66, 60, 0.4);
  }

  .node-textarea:focus {
    border-color: #994121;
  }

  .pairing-block {
    min-height: 120px;
    justify-content: center;
  }
</style>
