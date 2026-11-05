/** Presentation only: collected samples and stored chart history are never changed. */
const RESPONSE_MS = 150;

/** Two cascaded filters keep both the value and its velocity continuous on retarget. */
export function advanceTelemetryNumber(value, follower, target, elapsedMs) {
  if (
    ![value, follower, target].every(
      (item) => Number.isFinite(item) && item >= 0,
    ) ||
    elapsedMs > 1500
  )
    return { value: target, follower: target };
  const elapsed = Math.max(0, elapsedMs) / RESPONSE_MS;
  const decay = Math.exp(-elapsed);
  const next = {
    value: target + (value - target + (follower - target) * elapsed) * decay,
    follower: target + (follower - target) * decay,
  };
  const tolerance = Math.max(0.0001, target * 0.000001);
  if (
    Math.abs(next.value - target) < tolerance &&
    Math.abs(next.follower - target) < tolerance
  )
    return { value: target, follower: target };
  return next;
}

/** Avoid changing units back and forth when a rate hovers around a boundary. */
export function telemetryUnit(value, previous, maximum = 4) {
  let unit = Number.isInteger(previous)
    ? Math.max(0, Math.min(maximum, previous))
    : 0;
  if (previous === undefined) {
    while (unit < maximum && value >= 1000 ** (unit + 1)) unit++;
  } else {
    while (unit < maximum && value >= 1080 * 1000 ** unit) unit++;
    while (unit > 0 && value > 0 && value < 0.92 * 1000 ** unit) unit--;
  }
  return unit;
}

/** Cards and table cells share one readable label; never animate individual glyphs. */
export function paintTelemetryNumber(node, text) {
  if (node.textContent !== text) node.textContent = text;
}
