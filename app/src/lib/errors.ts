export type InvokeErrorPayload = {
  code?: string;
  message?: string;
  detail?: string | null;
  retryable?: boolean;
  retry_after_ms?: number | null;
};

export function getInvokeError(e: unknown): InvokeErrorPayload {
  if (e && typeof e === "object") {
    return e as InvokeErrorPayload;
  }

  return {
    code: "app.unclassified",
    message: String(e),
    detail: null,
    retryable: false,
  };
}

export function formatInvokeError(e: unknown): string {
  const err = getInvokeError(e);

  switch (err.code) {
    case "app.pin.incorrect":
      return "Incorrect PIN. Please try again.";
    case "app.pin.too_many_attempts":
      return "Too many incorrect PIN attempts.";
    case "app.pin.cooldown": {
      const seconds = Math.max(1, Math.ceil((err.retry_after_ms ?? 0) / 1000));
      return `Too many incorrect PIN attempts. Try again in ${seconds}s.`;
    }
    case "app.pin.invalid":
      return "PIN must contain the expected number of digits.";
    case "pairing.invalid_node_id":
      return "Enrollment token is invalid. Scan or paste the complete desktop token again.";
    case "app.setup_input":
      return "Setup input is invalid. Use the exact enrollment token for this desktop transaction.";
    case "network.connect":
    case "network.timeout":
      return "Could not reach the desktop. Keep the current Ferusa command open and resume with the same enrollment token.";
    case "app.biometric":
      return "Biometric authentication failed. Try again.";
    case "app.approval_key_auth_required":
      return "Biometric approval signing expired. Try again.";
    case "app.keystore.get":
    case "app.keystore.set":
    case "app.keystore.clear":
      return "Could not access secure phone storage. Keep the desktop transaction and enrollment token, then try again.";
    case "app.locked":
      return "Unlock the app before approving.";
    case "app.session_expired":
      return "Biometric session expired. Unlock again.";
    case "app.pending_missing":
      return "No pending request is available.";
    case "app.pending_mismatch":
      return "This approval no longer matches the pending request.";
    case "app.pairing_replacement.authorization":
      return "Pairing replacement authorization expired. Authenticate again and resume with the same enrollment token.";
    default:
      return err.message || String(e);
  }
}
