import { readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { MARKER, PACK, packById, packIds } from "./pack.ts";

const MARK = "0123456789abcdef";

describe("the built-in pack", () => {
  it("has a unique, well-formed id for every test", () => {
    expect(new Set(packIds).size).toBe(packIds.length);
    for (const id of packIds) expect(id).toMatch(/^[a-z][a-z0-9-]{0,63}$/);
  });

  it("runs every test harmlessly, and each cleans up after itself", async () => {
    for (const test of PACK) {
      const r = await test.perform(MARK);
      expect(r.cleanedUp).toBe(true);
      expect(r.did.length).toBeGreaterThan(0);
    }
    // No marker file is left anywhere in the temp directory.
    const left = (await readdir(tmpdir())).filter((f) => f.startsWith("openasy-sim-"));
    expect(left).toEqual([]);
  });

  it("only accepts a plain hex marker", () => {
    expect(MARKER.test(MARK)).toBe(true);
    expect(MARKER.test("../etc/passwd")).toBe(false);
    expect(MARKER.test("a; rm -rf /")).toBe(false);
    expect(MARKER.test("")).toBe(false);
  });

  it("looks a test up by id and has no id outside the pack", () => {
    expect(packById.get("discovery-whoami")).toBeDefined();
    expect(packById.get("read-etc-shadow")).toBeUndefined();
  });
});
