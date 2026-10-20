import { afterEach, describe, expect, it, vi } from "vitest";
import { deriveId, s256, safeEqual, signToken, verifyToken } from "../src/tokens.js";

const secret = "k".repeat(32);
const claims = { typ: "access" as const, sub: "u1", cid: "c1", aud: "https://x.example/mcp" };

afterEach(() => vi.useRealTimers());

describe("tokens", () => {
  it("round-trips signed claims", () => {
    const t = signToken(secret, claims, 60);
    expect(verifyToken(secret, t, "access")).toMatchObject(claims);
  });

  it("rejects the wrong type, so a code or refresh token is never an access token", () => {
    expect(verifyToken(secret, signToken(secret, { ...claims, typ: "refresh" }, 60), "access")).toBeUndefined();
    expect(verifyToken(secret, signToken(secret, { ...claims, typ: "code" }, 60), "access")).toBeUndefined();
  });

  it("rejects a token signed with another secret", () => {
    expect(verifyToken(secret, signToken("x".repeat(32), claims, 60), "access")).toBeUndefined();
  });

  it("rejects tampered claims", () => {
    const [, sig] = signToken(secret, claims, 60).split(".");
    const forged = Buffer.from(JSON.stringify({ ...claims, sub: "admin", exp: 9999999999 })).toString("base64url");
    expect(verifyToken(secret, `${forged}.${sig}`, "access")).toBeUndefined();
  });

  it("rejects malformed tokens", () => {
    for (const t of ["", "abc", "a.b.c", ".", "a."]) expect(verifyToken(secret, t, "access")).toBeUndefined();
  });

  it("expires", () => {
    vi.useFakeTimers();
    const t = signToken(secret, claims, 60);
    vi.advanceTimersByTime(61_000);
    expect(verifyToken(secret, t, "access")).toBeUndefined();
  });
});

describe("helpers", () => {
  it("computes PKCE S256 per the RFC 7636 test vector", () => {
    expect(s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  });

  it("derives stable, secret-dependent ids", () => {
    expect(deriveId(secret, "u_", "sam", "1234")).toBe(deriveId(secret, "u_", "sam", "1234"));
    expect(deriveId(secret, "u_", "sam", "1234")).not.toBe(deriveId(secret, "u_", "sam", "12345"));
    expect(deriveId(secret, "u_", "sam", "1234")).not.toBe(deriveId("y".repeat(32), "u_", "sam", "1234"));
    expect(deriveId(secret, "u_", "a")).toMatch(/^u_[0-9a-f]{32}$/);
  });

  it("compares in constant time and handles different lengths", () => {
    expect(safeEqual("abc", "abc")).toBe(true);
    expect(safeEqual("abc", "abd")).toBe(false);
    expect(safeEqual("abc", "abcd")).toBe(false);
  });
});
