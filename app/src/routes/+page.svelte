<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";

  import Setup from "$lib/components/Setup.svelte";
  import Biometric from "$lib/components/Biometric.svelte";
  import Approve from "$lib/components/Approve.svelte";
  import RecoveryApproval from "$lib/components/RecoveryApproval.svelte";
  import Idle from "$lib/components/Idle.svelte";
  import Success from "$lib/components/Success.svelte";
  import Failed from "$lib/components/Failed.svelte";
  import Reset from "$lib/components/Reset.svelte";
  import { formatInvokeError } from "$lib/errors";

  type Screen =
    | "loading"
    | "setup"
    | "biometric"
    | "approve"
    | "recovery"
    | "recovery_result"
    | "idle"
    | "success"
    | "failed"
    | "replace";

  type RequestPayload = {
    request_id: string;
    correlation_code?: number;
    entry_title?: string;
    action?: string;
    pin_digits?: number;
  };

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

  let screen = $state<Screen>("loading");
  let pendingRequest = $state<RequestPayload | null>(null);
  let pendingRecovery = $state<RecoveryRequest | null>(null);
  let recoveryOutcome = $state("");
  let recoverySucceeded = $state(false);
  let failReason = $state("");
  let queuedRequest = $state<RequestPayload | null>(null);
  let isUnlocked = $state(false);
  let loadingMessage = $state("Loading ferusa...");
  let retryMessage = $state("");
  let setupMode = $state<"initial" | "replacement">("initial");
  let enrollmentActive = $state(false);
  let hasPairing: boolean | null = null;
  let hasPendingEnrollment = false;
  let lifecycleRevision = 0;
  let recoveryRevision = 0;
  let latestRecoveryInstance: string | null = null;

  function clearSession() {
    lifecycleRevision += 1;
    recoveryRevision += 1;
    isUnlocked = false;
    pendingRequest = null;
    pendingRecovery = null;
    latestRecoveryInstance = null;
    queuedRequest = null;
    retryMessage = "";
    failReason = "";
    recoveryOutcome = "";
    recoverySucceeded = false;
    // Candidate enrollment remains mounted through recovery and lifecycle events.
    if (enrollmentActive || hasPendingEnrollment || hasPairing === false) {
      enrollmentActive = true;
      screen = "setup";
    } else {
      setupMode = "initial";
      screen = hasPairing ? "biometric" : "loading";
    }
  }

  async function refreshSetup() {
    const revision = ++lifecycleRevision;
    try {
      const { paired, pending } = await invoke<{ paired: boolean; pending: boolean }>("setup_status");
      if (revision !== lifecycleRevision) return;
      hasPairing = paired;
      hasPendingEnrollment = pending;
      // Durable completion can precede a setup callback interrupted by locking.
      if (paired && !pending && setupMode === "initial") enrollmentActive = false;
      if (!paired || pending || enrollmentActive) {
        if (!enrollmentActive) setupMode = paired ? "replacement" : "initial";
        enrollmentActive = true;
        if (screen !== "recovery" && screen !== "recovery_result") screen = "setup";
        if (pendingRecovery && document.visibilityState === "visible") screen = "recovery";
      } else if (!isUnlocked && (screen !== "recovery_result" || !recoverySucceeded)) {
        screen = "biometric";
      }
    } catch (e) {
      if (revision !== lifecycleRevision) return;
      console.error("setup_status failed:", formatInvokeError(e), e);
      if (hasPairing !== true || enrollmentActive) {
        enrollmentActive = true;
        screen = "setup";
      }
    }
  }

  async function reconcilePendingRequest(): Promise<RequestPayload | null | undefined> {
    const previousRequest = pendingRequest;
    const revision = lifecycleRevision;
    try {
      const request = await invoke<RequestPayload | null>("pending_request");
      // An event or lifecycle transition may have superseded this query.
      if (revision !== lifecycleRevision || pendingRequest !== previousRequest) return undefined;
      if (request) {
        if (isUnlocked && !enrollmentActive && !pendingRecovery) {
          pendingRequest = request;
          screen = "approve";
        } else {
          queuedRequest = request;
        }
      } else if (screen === "approve") {
        pendingRequest = null;
        retryMessage = "";
        screen = isUnlocked ? "idle" : "biometric";
      }
      return request;
    } catch (e) {
      console.error("pending_request failed:", formatInvokeError(e), e);
      return undefined;
    }
  }

  function handleRecovery(request: RecoveryRequest | null) {
    recoveryRevision += 1;
    if (document.visibilityState !== "visible") {
      pendingRecovery = null;
      return;
    }
    if (request) {
      if (["confirmed", "denied", "expired", "disconnected", "failed"].includes(request.phase)) {
        if (request.instance_id !== latestRecoveryInstance || (!enrollmentActive && !isUnlocked)) return;
        recoverySucceeded = request.phase === "confirmed";
        recoveryOutcome = ({
          confirmed: "Recovery file confirmed. Safely eject and store the drive separately from your phone and laptop.",
          denied: "Recovery request denied.",
          expired: "Recovery request expired. Start a new request on the laptop.",
          disconnected: "Recovery request disconnected. Reconnect and start a new request.",
          failed: "Recovery request failed. Check the laptop for details.",
        } as Record<string, string>)[request.phase];
        pendingRecovery = null;
        screen = "recovery_result";
        return;
      }
      latestRecoveryInstance = request.instance_id;
      pendingRecovery = request;
      if (isUnlocked || enrollmentActive) screen = "recovery";
    } else if (pendingRecovery && screen === "recovery") {
      recoverySucceeded = pendingRecovery.phase === "confirmed";
      recoveryOutcome = pendingRecovery.phase === "confirmed"
        ? "Recovery file confirmed. Safely eject and store the drive separately from your phone and laptop."
        : "Recovery request ended without confirmation. Check the laptop for details.";
      pendingRecovery = null;
      screen = "recovery_result";
    }
  }

  async function reconcilePendingRecovery() {
    const revision = lifecycleRevision;
    const requestRevision = recoveryRevision;
    try {
      const request = await invoke<RecoveryRequest | null>("pending_recovery");
      if (revision !== lifecycleRevision || requestRevision !== recoveryRevision) return;
      handleRecovery(request);
    } catch (e) {
      console.error("pending_recovery failed:", formatInvokeError(e), e);
    }
  }

  async function syncForegroundState() {
    const foreground = document.visibilityState === "visible";
    if (!foreground) clearSession();
    const revision = ++lifecycleRevision;
    try {
      await invoke("set_app_foreground", { foreground });
    } catch (e) {
      console.error("foreground state update failed:", formatInvokeError(e), e);
    }
    if (revision === lifecycleRevision) await refreshSetup();
  }

  onMount(() => {
    let unlisten: (() => void) | undefined;
    let unlistenSessionExpired: (() => void) | undefined;
    let unlistenSetupChanged: (() => void) | undefined;
    let unlistenRecovery: (() => void) | undefined;
    let disposed = false;
    const slowTimer = window.setTimeout(() => {
      loadingMessage = "Opening encrypted vault...";
    }, 1500);
    const verySlowTimer = window.setTimeout(() => {
      loadingMessage = "Still opening encrypted vault. First launch after security upgrade can take longer.";
    }, 6000);
    const reconcileTimer = window.setInterval(() => {
      void reconcilePendingRequest();
      void reconcilePendingRecovery();
    }, 2000);

    function handleAuthRequest(request: RequestPayload) {
      retryMessage = "";
      if (isUnlocked && !enrollmentActive && !pendingRecovery) {
        pendingRequest = request;
        screen = "approve";
      } else {
        queuedRequest = request;
      }
    }

    const registerListeners = async () => {
      try {
        const authUnlisten = await listen<RequestPayload>(
          "ferusa://auth-request",
          (event) => handleAuthRequest(event.payload),
        );
        if (disposed) {
          authUnlisten();
        } else {
          unlisten = authUnlisten;
        }
      } catch (e) {
        console.error("auth-request listener failed:", formatInvokeError(e), e);
      }

      try {
        const sessionExpiredUnlisten = await listen(
          "ferusa://session-expired",
          () => {
            clearSession();
            void refreshSetup();
          },
        );
        if (disposed) {
          sessionExpiredUnlisten();
        } else {
          unlistenSessionExpired = sessionExpiredUnlisten;
        }
      } catch (e) {
        console.error(
          "session-expired listener failed:",
          formatInvokeError(e),
          e,
        );
      }

      try {
        const setupChangedUnlisten = await listen("ferusa://setup-changed", () => {
          clearSession();
          void refreshSetup();
        });
        if (disposed) {
          setupChangedUnlisten();
        } else {
          unlistenSetupChanged = setupChangedUnlisten;
        }
      } catch (e) {
        console.error("setup-changed listener failed:", formatInvokeError(e), e);
      }

      try {
        const recoveryUnlisten = await listen<RecoveryRequest | null>(
          "ferusa://recovery-request", (event) => handleRecovery(event.payload),
        );
        if (disposed) recoveryUnlisten();
        else unlistenRecovery = recoveryUnlisten;
      } catch (e) {
        console.error("recovery-request listener failed:", formatInvokeError(e), e);
      }

      try {
        await reconcilePendingRequest();
        await reconcilePendingRecovery();
      } catch (e) {
        console.error("initial pending_request failed:", formatInvokeError(e), e);
      }
    };

    const init = async () => {
      try {
        await refreshSetup();
      } finally {
        window.clearTimeout(slowTimer);
        window.clearTimeout(verySlowTimer);
      }
    };

    void init();
    void registerListeners();
    void syncForegroundState();

    return () => {
      disposed = true;
      lifecycleRevision += 1;
      window.clearTimeout(slowTimer);
      window.clearTimeout(verySlowTimer);
      window.clearInterval(reconcileTimer);
      unlisten?.();
      unlistenSessionExpired?.();
      unlistenSetupChanged?.();
      unlistenRecovery?.();
    };
  });

  function onSetupComplete() {
    lifecycleRevision += 1;
    hasPairing = true;
    hasPendingEnrollment = false;
    enrollmentActive = false;
    isUnlocked = false;
    pendingRequest = null;
    queuedRequest = null;
    pendingRecovery = null;
    setupMode = "initial";
    if (screen !== "recovery_result" || !recoverySucceeded) screen = "biometric";
  }

  function onUnlocked() {
    if (document.visibilityState !== "visible" || hasPairing !== true || enrollmentActive || hasPendingEnrollment) return;
    lifecycleRevision += 1;
    isUnlocked = true;

    if (queuedRequest) {
      pendingRequest = queuedRequest;
      queuedRequest = null;
      screen = "approve";
    } else if (pendingRecovery) {
      screen = "recovery";
    } else {
      screen = "idle";
    }
  }

  function onLocked() {
    clearSession();
    void refreshSetup();
  }

  function isCurrentRequest(request: RequestPayload) {
    return screen === "approve" && JSON.stringify(pendingRequest) === JSON.stringify(request);
  }

  function onApprovalLocked(request: RequestPayload) {
    if (isCurrentRequest(request)) onLocked();
  }

  function onApproved(request: RequestPayload) {
    if (!isCurrentRequest(request)) return;
    screen = "success";
  }

  function onDenied(request: RequestPayload) {
    if (!isCurrentRequest(request)) return;
    failReason = "";
    screen = "failed";
  }

  async function onFailed(submittedRequest: RequestPayload, payload?: { reason: string }) {
    if (!isCurrentRequest(submittedRequest)) return;
    const reason = payload?.reason ?? "Something went wrong. Please try again.";
    let request: RequestPayload | null;
    try {
      request = await invoke<RequestPayload | null>("pending_request");
    } catch {
      if (isCurrentRequest(submittedRequest)) {
        retryMessage = `${reason} Checking the pending request…`;
      }
      return;
    }
    if (!isCurrentRequest(submittedRequest)) return;
    pendingRequest = request;
    if (request) {
      retryMessage = JSON.stringify(request) === JSON.stringify(submittedRequest) ? reason : "";
      screen = "approve";
    } else if (request === null) {
      failReason = reason;
      screen = "failed";
    }
  }

  function onResultDone() {
    pendingRequest = null;
    failReason = "";
    screen = isUnlocked ? "idle" : "biometric";
  }

  function onRecoveryDenied(instanceId: string) {
    if (pendingRecovery?.instance_id !== instanceId) return;
    recoveryRevision += 1;
    pendingRecovery = null;
    recoveryOutcome = "Recovery request denied.";
    recoverySucceeded = false;
    screen = "recovery_result";
  }

  function onRecoveryResultDone() {
    recoveryOutcome = "";
    recoverySucceeded = false;
    screen = enrollmentActive ? "setup" : isUnlocked ? "idle" : hasPairing ? "biometric" : "setup";
  }

  function onReplace() {
    lifecycleRevision += 1;
    screen = "replace";
  }

  function onReplacementAuthorized() {
    lifecycleRevision += 1;
    setupMode = "replacement";
    enrollmentActive = true;
    pendingRequest = null;
    queuedRequest = null;
    screen = "setup";
  }

  async function onReplacementCancel() {
    const revision = ++lifecycleRevision;
    try {
      await invoke("cancel_pairing_replacement");
    } catch (e) {
      console.error("cancel_pairing_replacement failed:", formatInvokeError(e), e);
    }
    if (revision !== lifecycleRevision) return;
    enrollmentActive = false;
    setupMode = "initial";
    await refreshSetup();
    if (!enrollmentActive) screen = isUnlocked ? "idle" : "biometric";
  }
</script>

<main>
  {#if enrollmentActive}
    {#key setupMode}
      <div hidden={screen !== "setup"}>
        <Setup
          mode={setupMode}
          oncomplete={onSetupComplete}
          oncancel={setupMode === "replacement" ? onReplacementCancel : undefined}
        />
      </div>
    {/key}
  {/if}
  {#if screen === "loading"}
    <div class="center"><p>{loadingMessage}</p></div>
  {:else if screen === "biometric"}
    <Biometric onunlocked={onUnlocked} />
  {:else if screen === "replace"}
    <Reset onauthorized={onReplacementAuthorized} oncancel={onReplacementCancel} />
  {:else if screen === "approve"}
    {#if pendingRequest}
      {#key JSON.stringify(pendingRequest)}
      <Approve
        request={pendingRequest}
        {retryMessage}
        onapproved={onApproved}
        ondenied={onDenied}
        onfailed={onFailed}
        onlocked={onApprovalLocked}
      />
      {/key}
    {/if}
  {:else if screen === "recovery"}
    {#if pendingRecovery}
      {#key pendingRecovery.instance_id}
        <RecoveryApproval request={pendingRecovery} ondenied={onRecoveryDenied} />
      {/key}
    {/if}
  {:else if screen === "recovery_result"}
    {#if recoverySucceeded}
      <Success
        title="Recovery confirmed"
        message={recoveryOutcome}
        ondone={onRecoveryResultDone}
      />
    {:else}
      <Failed
        title="Recovery not confirmed"
        reason={recoveryOutcome}
        ondone={onRecoveryResultDone}
      />
    {/if}
  {:else if screen === "success"}
    <Success request={pendingRequest} ondone={onResultDone} />
  {:else if screen === "failed"}
    <Failed
      request={pendingRequest}
      reason={failReason}
      ondone={onResultDone}
    />
  {:else if screen === "idle"}
    <Idle onlocked={onLocked} onreplace={onReplace} />
  {/if}
</main>

<svelte:document onvisibilitychange={syncForegroundState} />

<style>
  :global(body) {
    margin: 0;
    background: #0f0f0f;
    color: #f0f0f0;
    font-family: system-ui, sans-serif;
  }
  :global(.sveltekit-body) {
    display: contents;
  }
  .center {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100vh;
  }
</style>
