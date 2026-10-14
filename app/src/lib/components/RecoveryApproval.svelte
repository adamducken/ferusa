<script lang="ts">
  import { onDestroy } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import {
    AlertTriangle,
    Check,
    CheckCircle,
    Clock3,
    Laptop,
    LockKeyhole,
    ShieldCheck,
    Usb,
    X,
    XCircle,
  } from "lucide-svelte";
  import { formatInvokeError } from "$lib/errors";
  import SecurityFrame from "./SecurityFrame.svelte";

  type RecoveryRequest = {
    request_id: string;
    instance_id: string;
    purpose: string;
    correlation_code: number;
    pairing_id: string;
    phase: "review" | "waiting_for_laptop" | "verifying" | "waiting_for_usb" | "confirmed" | "denied" | "expired" | "disconnected" | "failed";
    remaining_ms: number;
    error?: string;
  };

  let { request, ondenied }: {
    request: RecoveryRequest;
    ondenied: (instanceId: string) => void;
  } = $props();

  let pendingAction = $state<"approve" | "deny" | null>(null);
  let submitting = $derived(pendingAction !== null);
  let confirmed = $state(false);
  let error = $state("");
  let disposed = false;
  onDestroy(() => { disposed = true; });

  let phaseText = $derived(({
    review: "Review the warning and match the code on your laptop.",
    waiting_for_laptop: "Waiting for master password and both PINs on the laptop.",
    verifying: "Checking both PINs on this phone.",
    waiting_for_usb: "Waiting for the laptop to write and verify the USB file.",
    confirmed: "The recovery file was confirmed. Safely eject the drive and store it securely.",
    denied: "Recovery request denied.",
    expired: "Recovery request expired.",
    disconnected: "Recovery request disconnected.",
    failed: "Recovery request failed. Check the laptop for details.",
  })[request.phase]);

  const steps = ["Review", "Laptop", "Verify", "USB"];

  let stepNumber = $derived(({
    review: 1,
    waiting_for_laptop: 2,
    verifying: 3,
    waiting_for_usb: 4,
    confirmed: 4,
    denied: 0,
    expired: 0,
    disconnected: 0,
    failed: 0,
  })[request.phase]);

  let phaseTitle = $derived(({
    review: "Review & approve",
    waiting_for_laptop: "Continue on your laptop",
    verifying: "Verifying your PINs",
    waiting_for_usb: "Preparing your recovery drive",
    confirmed: "Recovery file confirmed",
    denied: "Request denied",
    expired: "Request expired",
    disconnected: "Connection lost",
    failed: "Recovery could not finish",
  })[request.phase]);

  let purposeLabel = $derived(({
    create: "Create recovery file",
    confirm_existing: "Confirm existing file",
    initial_setup: "Complete setup",
    password_change: "Change master password",
    pairing_change: "Replace paired phone",
    lost_phone_recovery: "Recover with a new phone",
  } as Record<string, string>)[request.purpose] ?? request.purpose.replaceAll("_", " "));

  let inProgress = $derived(
    request.phase === "waiting_for_laptop" ||
    request.phase === "verifying" ||
    request.phase === "waiting_for_usb",
  );
  let secondsRemaining = $derived(Math.max(0, Math.ceil(request.remaining_ms / 1000)));

  async function confirm() {
    const instanceId = request.instance_id;
    if (pendingAction !== null || confirmed || request.phase !== "review") return;
    pendingAction = "approve";
    error = "";
    try {
      await invoke("confirm_recovery", { instanceId });
      if (!disposed && request.instance_id === instanceId) confirmed = true;
    } catch (cause) {
      if (!disposed && request.instance_id === instanceId) error = formatInvokeError(cause);
    } finally {
      if (!disposed && request.instance_id === instanceId) pendingAction = null;
    }
  }

  async function deny() {
    const instanceId = request.instance_id;
    if (pendingAction !== null || !["review", "waiting_for_laptop", "verifying", "waiting_for_usb"].includes(request.phase)) return;
    pendingAction = "deny";
    error = "";
    try {
      await invoke("deny_recovery", { instanceId });
      if (!disposed && request.instance_id === instanceId) ondenied(instanceId);
    } catch (cause) {
      if (!disposed && request.instance_id === instanceId) error = formatInvokeError(cause);
    } finally {
      if (!disposed && request.instance_id === instanceId) pendingAction = null;
    }
  }
</script>

<SecurityFrame codeGap="14px">
  <div class="recovery-content">
    <div class="recovery-progress">
      <div class="progress-header">
        <span class="progress-label">Recovery Drive</span>
        <span class="progress-step">
          {#if request.phase === "confirmed"}
            Complete
          {:else if stepNumber === 0}
            Request ended
          {:else}
            Step {stepNumber} of {steps.length}
          {/if}
        </span>
      </div>
      <ol class="recovery-steps" aria-label="Recovery progress">
        {#each steps as label, index (label)}
          <li
            class={[
              "recovery-step",
              { active: index + 1 <= stepNumber },
            ]}
            aria-current={index + 1 === stepNumber ? "step" : undefined}
          >
            <span class="step-track" aria-hidden="true"></span>
            <span class="step-label">{label}</span>
          </li>
        {/each}
      </ol>
    </div>

    <div class="title">
      <h1>Recovery drive approval</h1>
      <p>
        {request.phase === "review"
          ? "Review the warning and match the code on your laptop."
          : "Keep track of your recovery file below."}
      </p>
    </div>

    <div class="code-block recovery-code">
      <span class="code-label">CORRELATION CODE</span>
      <div
        class="code-value"
        aria-label={`Correlation code ${String(request.correlation_code).padStart(4, "0")}`}
      >
        {String(request.correlation_code).padStart(4, "0")}
      </div>
      <div class="operation-row">
        <span class="meta-label">Operation</span>
        <span class="operation-value">{purposeLabel}</span>
      </div>
    </div>

    {#if request.phase === "review"}
      <section class="warning-card" aria-labelledby="recovery-warning-title">
        <div class="warning-heading">
          <span class="warning-icon" aria-hidden="true">
            <AlertTriangle size={17} strokeWidth={1.8} />
          </span>
          <h2 id="recovery-warning-title">Before you approve</h2>
        </div>
        <p class="warning-intro">
          This recovery file can replace your phone when used with your
          <strong>master password and both phone PINs.</strong>
          Keep it in a secure location, separate from your phone, laptop, and vault
          backups. Do not carry it around with your phone. Anyone who copies it can
          attempt to guess those credentials without your phone's biometric checks
          or PIN attempt limits.
        </p>
        <ul class="warning-list">
          <li>
            Keep this recovery drive in a secure location, separate from your
            phone, laptop, and any vault backups. Do not carry it around with your
            phone.
          </li>
          <li>
            Recovery uses your master password and both phone PINs. No new password.
          </li>
          <li>
            This drive restores access, not your vault data. If you lose the vault
            and have no separate copy, recovery cannot restore your passwords.
          </li>
        </ul>
        <p class="warning-intro">
          You also need your encrypted vault to recover your passwords. This
          recovery drive contains no vault data. If you lose the vault and have no
          separate backup, this file cannot restore it.
        </p>
        {#if request.purpose === "password_change" || request.purpose === "pairing_change" || request.purpose === "lost_phone_recovery"}
          <p class="warning-intro">
            Refresh your recovery file when your master password or either phone
            PIN changes. Older copies still require the password and PINs used
            when they were created; changing your credentials does not revoke
            those copies.
          </p>
        {/if}
      </section>
    {:else}
      <div
        class={[
          "status-panel",
          { success: request.phase === "confirmed", ended: stepNumber === 0 },
        ]}
        role="status"
      >
        <div class="status-icon" aria-hidden="true">
          {#if request.phase === "confirmed"}
            <CheckCircle size={32} strokeWidth={1.5} />
          {:else if request.phase === "waiting_for_laptop"}
            <Laptop size={32} strokeWidth={1.5} />
          {:else if request.phase === "verifying"}
            <ShieldCheck size={32} strokeWidth={1.5} />
          {:else if request.phase === "waiting_for_usb"}
            <Usb size={32} strokeWidth={1.5} />
          {:else}
            <XCircle size={32} strokeWidth={1.5} />
          {/if}
        </div>
        <div class="status-copy">
          <h2>{phaseTitle}</h2>
          <p>{phaseText}</p>
        </div>
        {#if inProgress}
          <span class="status-activity">
            <span class="spinner-inline spinner-deny" aria-hidden="true"></span>
            Keep this app open
          </span>
        {/if}
      </div>
    {/if}

    {#if error || request.error}
      <div class="error-box recovery-error" role="alert">{error || request.error}</div>
    {/if}

    {#if request.phase === "review" || inProgress}
      <div class="request-meta">
        <span class="request-note">
          <LockKeyhole size={13} aria-hidden="true" />
          {request.phase === "review" ? "Paired laptop request" : "Secure connection"}
        </span>
        <span
          class={["time-remaining", { urgent: secondsRemaining <= 15 }]}
          aria-label={`Time remaining: ${secondsRemaining} seconds`}
        >
          <Clock3 size={13} aria-hidden="true" />
          {secondsRemaining}s left
        </span>
      </div>
    {/if}

    {#if request.phase === "review"}
      <div class="btn-stack">
        <button
          class="btn btn-approve"
          onclick={confirm}
          disabled={submitting || confirmed}
          aria-label="Approve recovery file creation"
        >
          {#if pendingAction === "approve" || confirmed}
            <span class="spinner-inline" aria-hidden="true"></span>
            {confirmed ? "Waiting for laptop…" : "Approving…"}
          {:else}
            <Check size={18} aria-hidden="true" />
            Approve recovery file
          {/if}
        </button>
        <button
          class="btn btn-deny"
          onclick={deny}
          disabled={submitting}
          aria-label="Deny recovery file creation"
        >
          {#if pendingAction === "deny"}
            <span class="spinner-inline spinner-deny" aria-hidden="true"></span>
            Denying…
          {:else}
            <X size={18} aria-hidden="true" />
            Deny Request
          {/if}
        </button>
      </div>
    {:else if inProgress}
      <div class="btn-stack">
        <button
          class="btn btn-cancel"
          onclick={deny}
          disabled={submitting}
          aria-label="Cancel recovery file creation"
        >
          {#if pendingAction === "deny"}
            <span class="spinner-inline spinner-deny" aria-hidden="true"></span>
            Cancelling…
          {:else}
            <X size={18} aria-hidden="true" />
            Cancel request
          {/if}
        </button>
      </div>
    {/if}
  </div>
</SecurityFrame>

<style>
  .recovery-content {
    width: 100%;
    min-width: 0;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 20px;
  }

  .recovery-progress {
    width: 100%;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .recovery-steps {
    list-style: none;
    display: flex;
    gap: 6px;
    padding: 0;
    margin: 0;
  }

  .recovery-step {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 7px;
  }

  .step-track {
    height: 5px;
    border-radius: 999px;
    background: #e3e3de;
    transition: background 0.3s ease;
  }

  .step-label {
    font-size: 10px;
    font-weight: 600;
    color: #766a63;
    text-align: center;
  }

  .active .step-track {
    background: #994121;
  }

  .active .step-label {
    color: #994121;
  }

  .recovery-code .code-value {
    font-variant-numeric: tabular-nums;
    padding-left: 0.12em;
  }

  .operation-row {
    width: 100%;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding-top: 14px;
    border-top: 1px solid #e9e5dd;
  }

  .operation-value {
    font-size: 12px;
    font-weight: 600;
    line-height: 1.4;
    color: #994121;
    text-align: right;
    overflow-wrap: anywhere;
  }

  .warning-card {
    width: 100%;
    box-sizing: border-box;
    background: #faf9f4;
    border-radius: 24px;
    padding: 18px 20px;
    color: #56423c;
  }

  .warning-heading {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .warning-icon {
    width: 32px;
    height: 32px;
    flex: 0 0 auto;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: 50%;
    background: #f0e5d9;
    color: #994121;
  }

  .warning-heading h2 {
    font-size: 14px;
    font-weight: 700;
    color: #1b1c19;
    margin: 0;
  }

  .warning-intro {
    margin: 12px 0 14px;
    font-size: 13px;
    line-height: 1.5;
  }

  .warning-intro strong {
    font-weight: 600;
    color: #994121;
  }

  .warning-list {
    list-style: none;
    display: flex;
    flex-direction: column;
    gap: 12px;
    margin: 0;
    padding: 14px 0 0;
    border-top: 1px solid #e9e5dd;
  }

  .warning-list li {
    position: relative;
    padding-left: 14px;
    font-size: 12px;
    line-height: 1.5;
  }

  .warning-list li::before {
    content: "";
    position: absolute;
    left: 0;
    top: 7px;
    width: 4px;
    height: 4px;
    border-radius: 50%;
    background: #b5775e;
  }

  .status-panel {
    width: 100%;
    box-sizing: border-box;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 18px;
    padding: 28px 20px 22px;
    border-radius: 24px;
    background: #faf9f4;
    text-align: center;
  }

  .status-icon {
    width: 64px;
    height: 64px;
    border-radius: 50%;
    background: #f0e5d9;
    color: #994121;
    box-shadow: 0 0 0 5px #f5eee5;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .status-copy h2 {
    margin: 0;
    font-size: 16px;
    font-weight: 700;
    color: #1b1c19;
  }

  .status-copy p {
    margin: 8px 0 0;
    font-size: 13px;
    line-height: 1.5;
    color: #56423c;
  }

  .status-activity {
    --security-spinner-size: 12px;
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 11px;
    font-weight: 500;
    color: #766a63;
  }

  .success .status-icon {
    background: #edf7ee;
    color: #2e7d32;
    box-shadow: 0 0 0 5px #d4edda;
  }

  .ended .status-icon {
    background: #fff2ee;
    color: #8a2f16;
    box-shadow: 0 0 0 5px #f8e5dc;
  }

  .request-meta {
    width: 100%;
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 8px;
  }

  .request-note,
  .time-remaining {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 11px;
    font-weight: 500;
    color: #766a63;
  }

  .time-remaining {
    padding: 5px 8px;
    border-radius: 999px;
    background: #f5f4ef;
    font-variant-numeric: tabular-nums;
  }

  .time-remaining.urgent {
    color: #8a2f16;
    background: #fff2ee;
  }

  .recovery-content .error-box.recovery-error {
    background: #fff2ee;
    color: #8a2f16;
    border-color: #f0c4b6;
    border-radius: 18px;
    padding: 12px 14px;
    font-size: 13px;
  }

  .btn:focus-visible {
    outline: 2px solid #994121;
    outline-offset: 4px;
  }

  @media (max-width: 380px) {
    .recovery-content {
      gap: 18px;
    }

    .warning-card {
      padding: 16px;
    }

    .title {
      --security-title-size: 24px;
    }
  }
</style>
