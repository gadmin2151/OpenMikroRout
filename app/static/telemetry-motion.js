/** Presentation only: collected samples and stored chart history are never changed. */
const RESPONSE_MS = 150;
const DIGIT_MS = 180;
const reels = new WeakMap();

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

/** Rebase an identical part of the reel and take the shortest route to the next digit. */
export function telemetryDigitPositions(position, digit) {
  const from = 10 + (((position % 10) + 10) % 10);
  let to = 10 + digit;
  if (to - from > 5) to -= 10;
  if (to - from < -5) to += 10;
  return { from, to };
}

function transform(position) {
  return `translateY(${-position * 1.25}em)`;
}

export function stopTelemetryDigits(node) {
  const previous = reels.get(node);
  if (!previous) return;
  for (const digit of previous.digits.values()) digit.animation?.cancel();
  reels.delete(node);
}

/** Headline digits roll in persistent slots; table cells retain quiet, ordinary text. */
export function paintTelemetryNumber(node, text, animate) {
  if (
    !animate ||
    !node.classList.contains("telemetry-value") ||
    typeof node.animate !== "function" ||
    !/\d/.test(text)
  ) {
    stopTelemetryDigits(node);
    node.removeAttribute("aria-label");
    if (node.textContent !== text) node.textContent = text;
    node.dataset.displayText = text;
    return;
  }
  const previous = reels.get(node) || { text: "", digits: new Map() };
  if (previous.text === text) return;
  const owner = node.ownerDocument;
  const digits = new Map();
  const children = [];
  let remaining = [...text].filter((char) => /\d/.test(char)).length;
  let literal = "";
  const flush = () => {
    if (!literal) return;
    const span = owner.createElement("span");
    span.className = "telemetry-number-literal";
    span.textContent = literal;
    span.setAttribute("aria-hidden", "true");
    children.push(span);
    literal = "";
  };
  for (const char of text) {
    if (!/\d/.test(char)) {
      literal += char;
      continue;
    }
    flush();
    const key = --remaining;
    const value = Number(char);
    let digit = previous.digits.get(key);
    if (!digit) {
      const slot = owner.createElement("span");
      slot.className = "telemetry-number-digit";
      slot.setAttribute("aria-hidden", "true");
      const strip = owner.createElement("span");
      strip.className = "telemetry-number-reel";
      for (let index = 0; index < 30; index++) {
        const glyph = owner.createElement("span");
        glyph.textContent = String(index % 10);
        strip.append(glyph);
      }
      slot.append(strip);
      digit = { slot, strip, value, from: 10 + value, to: 10 + value };
      strip.style.transform = transform(digit.to);
    } else if (digit.value !== value) {
      const progress = Math.min(
        1,
        Math.max(0, Number(digit.animation?.currentTime || 0) / DIGIT_MS),
      );
      const current = digit.from + (digit.to - digit.from) * progress;
      const { from, to } = telemetryDigitPositions(current, value);
      digit.animation?.cancel();
      digit.strip.style.transform = transform(to);
      digit.animation = digit.strip.animate(
        [{ transform: transform(from) }, { transform: transform(to) }],
        { duration: DIGIT_MS, easing: "linear" },
      );
      digit.from = from;
      digit.to = to;
      digit.value = value;
    }
    digits.set(key, digit);
    children.push(digit.slot);
  }
  flush();
  for (const [key, digit] of previous.digits)
    if (!digits.has(key)) digit.animation?.cancel();
  node.replaceChildren(...children);
  node.setAttribute("aria-label", text);
  node.dataset.displayText = text;
  reels.set(node, { text, digits });
}
