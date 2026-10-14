<script lang="ts">
  import { onMount } from "svelte";
  import { XCircle } from "lucide-svelte";
  import SecurityFrame from "./SecurityFrame.svelte";

  type RequestPayload = {
    entry_title?: string;
    action?: string;
  };

  let {
    request = null,
    title = "Denied",
    reason = "",
    ondone,
  }: {
    request?: RequestPayload | null;
    title?: string;
    reason?: string;
    ondone?: () => void;
  } = $props();

  onMount(() => {
    const timer = setTimeout(() => {
      ondone?.();
    }, 2800);
    return () => clearTimeout(timer);
  });

  function actionLabel(action: string): string {
    return (action ?? "").toUpperCase();
  }
</script>

<SecurityFrame variant="status">
        <div class="icon-wrap deny-ring">
          <XCircle size={48} strokeWidth={1.5} />
        </div>

        <div class="title">
          <h1>{title}</h1>
          {#if reason}
            <p>{reason}</p>
          {:else if request?.entry_title}
            <p>
              Request for <strong>{request.entry_title}</strong> was denied.
            </p>
          {:else}
            <p>This request was not approved.</p>
          {/if}
        </div>

        {#if request?.action}
          <div class="meta-row">
            <span class="meta-label">Action</span>
            <span class="meta-value action-badge"
              >{actionLabel(request.action)}</span
            >
          </div>
        {/if}

        <div class="progress-bar">
          <div class="progress-fill"></div>
        </div>
</SecurityFrame>

<style>
  .icon-wrap {
    width: 88px;
    height: 88px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    animation: popIn 0.4s cubic-bezier(0.34, 1.56, 0.64, 1) 0.1s both;
  }

  @keyframes popIn {
    from {
      transform: scale(0.5);
      opacity: 0;
    }
    to {
      transform: scale(1);
      opacity: 1;
    }
  }

  .deny-ring {
    background: #fef2f2;
    color: #991b1b;
    box-shadow: 0 0 0 6px #fee2e2;
  }

  .progress-bar {
    width: 100%;
    height: 4px;
    background: #e3e3de;
    border-radius: 999px;
    overflow: hidden;
    margin-top: 4px;
  }

  .progress-fill {
    height: 100%;
    width: 0%;
    background: #991b1b;
    border-radius: 999px;
    animation: fillProgress 2.8s linear forwards;
  }

  @keyframes fillProgress {
    from {
      width: 0%;
    }
    to {
      width: 100%;
    }
  }
</style>
