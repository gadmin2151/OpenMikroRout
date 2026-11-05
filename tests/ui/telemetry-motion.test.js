import test from "node:test";
import assert from "node:assert/strict";
import {
  advanceTelemetryNumber,
  paintTelemetryNumber,
  telemetryUnit,
} from "../../app/static/telemetry-motion.js";

test("continuous following is independent of frame rate and does not restart with polling", () => {
  const run = (interval, steps) => {
    let state = { value: 0, follower: 0 };
    for (let index = 0; index < steps; index++)
      state = advanceTelemetryNumber(
        state.value,
        state.follower,
        100,
        interval,
      );
    return state;
  };
  const sixtyHz = run(1000 / 60, 60);
  const thirtyHz = run(1000 / 30, 30);
  assert.ok(Math.abs(sixtyHz.value - thirtyHz.value) < 0.000001);
  assert.ok(sixtyHz.value > 99 && sixtyHz.value < 100);
});

test("new targets preserve displayed value and velocity instead of restarting easing", () => {
  let state = { value: 0, follower: 0 };
  for (let frame = 0; frame < 12; frame++)
    state = advanceTelemetryNumber(state.value, state.follower, 100, 16);
  const before = state.value;
  const following = advanceTelemetryNumber(
    state.value,
    state.follower,
    200,
    16,
  );
  assert.ok(following.value > before && following.value - before < 10);
  // A downward target also follows continuously and never produces negative rates.
  for (let frame = 0; frame < 240; frame++) {
    state = advanceTelemetryNumber(state.value, state.follower, 0, 16);
    assert.ok(state.value >= 0 && state.follower >= 0);
  }
  assert.equal(state.value, 0);
});

test("missing readings and a suspended tab settle directly rather than inventing motion", () => {
  assert.deepEqual(advanceTelemetryNumber(100, 100, null, 16), {
    value: null,
    follower: null,
  });
  assert.deepEqual(advanceTelemetryNumber(10, 20, 300, 2000), {
    value: 300,
    follower: 300,
  });
  assert.deepEqual(advanceTelemetryNumber(10, 20, 300, 0), {
    value: 10,
    follower: 20,
  });
});

test("unit hysteresis prevents flickering near 1000 while preserving real scale changes", () => {
  assert.equal(telemetryUnit(1000, undefined), 1);
  assert.equal(telemetryUnit(999, 1), 1);
  assert.equal(telemetryUnit(1001, 0), 0);
  assert.equal(telemetryUnit(1100, 0), 1);
  assert.equal(telemetryUnit(900, 1), 0);
  assert.equal(telemetryUnit(0, 2), 2);
  assert.equal(telemetryUnit(2e18, undefined, 6), 6);
});

test("rapid metric changes replace a complete reading without spinning or split digits", () => {
  let text = "",
    writes = 0;
  const node = {
    get textContent() {
      return text;
    },
    set textContent(value) {
      text = value;
      writes++;
    },
    animate() {
      assert.fail("Live readings must not animate individual digits");
    },
    replaceChildren() {
      assert.fail("A reading must stay a single text node");
    },
  };
  for (const value of [
    "41,8 Кбит/с",
    "86,2 Кбит/с",
    "7",
    "999,9 Кбит/с",
    "1,1 Мбит/с",
    "0 бит/с",
    "—",
  ]) {
    paintTelemetryNumber(node, value);
    assert.equal(node.textContent, value);
  }
  assert.equal(writes, 7);
  paintTelemetryNumber(node, "—");
  assert.equal(writes, 7, "An unchanged reading must not rewrite the DOM");
});
