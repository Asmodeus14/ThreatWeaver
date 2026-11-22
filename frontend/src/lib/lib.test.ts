import { describe, expect, it } from "vitest";
import { ALL_VERDICTS, verdictInfo } from "./verdicts";
import { bytes, pct, shortHash } from "./format";

describe("verdicts", () => {
  it("maps every server verdict to a label, tone and shape key", () => {
    for (const v of ALL_VERDICTS) {
      const info = verdictInfo(v);
      expect(info.label.length).toBeGreaterThan(0);
      expect(info.key).not.toBe("");
    }
  });
  it("orders malicious before suspicious before benign", () => {
    expect(verdictInfo("Known Malicious").rank).toBeLessThan(verdictInfo("Suspicious").rank);
    expect(verdictInfo("Suspicious").rank).toBeLessThan(verdictInfo("Likely Benign").rank);
  });
  it("never treats an unknown verdict as benign", () => {
    const u = verdictInfo("Something new");
    expect(u.tone).toBe("muted");
    expect(u.key).not.toBe("benign");
  });
  it("flags errors as needing attention (unknown is not safe)", () => {
    expect(verdictInfo("Analysis Error").needsAttention).toBe(true);
    expect(verdictInfo("Trusted Signer").needsAttention).toBe(false);
  });
});

describe("format", () => {
  it("formats percentages and missing values", () => {
    expect(pct(0.955)).toBe("95.5%");
    expect(pct(null)).toBe("—");
  });
  it("formats sizes", () => {
    expect(bytes(1024)).toBe("1.0 KB");
    expect(bytes(5)).toBe("5 B");
  });
  it("shortens hashes", () => {
    expect(shortHash("a".repeat(64), 8)).toBe("aaaaaaaa…");
  });
});

import { zoneOf } from "../components/VerdictScale";

describe("score zones follow the detector's real thresholds", () => {
  const t = { low: 0.789, high: 0.9815, lowLabel: "", highLabel: "" };
  it("places scores in the right zone, inclusive at each threshold", () => {
    expect(zoneOf(0.5, t)).toBe("low");
    expect(zoneOf(0.789, t)).toBe("review");
    expect(zoneOf(0.95, t)).toBe("review");
    expect(zoneOf(0.9815, t)).toBe("high");
  });
  it("has no high zone when both thresholds are equal (legacy model)", () => {
    const legacy = { low: 0.3, high: 0.3, lowLabel: "", highLabel: "" };
    expect(zoneOf(0.9, legacy)).toBe("review");
  });
});
