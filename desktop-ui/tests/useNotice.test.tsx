import { act, renderHook } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { useNotice } from "../src/useNotice";

afterEach(() => vi.useRealTimers());

test("routine notices expire while errors remain until dismissed", () => {
  vi.useFakeTimers();
  const { result } = renderHook(useNotice);
  act(() => result.current.showNotice("Generation queued"));
  act(() => vi.advanceTimersByTime(4999));
  expect(result.current.notice?.message).toBe("Generation queued");
  act(() => vi.advanceTimersByTime(1));
  expect(result.current.notice).toBeNull();
  act(() => result.current.showError("Could not start generation"));
  act(() => vi.advanceTimersByTime(10000));
  expect(result.current.notice?.kind).toBe("error");
  act(() => result.current.dismiss());
  expect(result.current.notice).toBeNull();
});

test("a newer message cancels the previous notice timer", () => {
  vi.useFakeTimers();
  const { result } = renderHook(useNotice);
  act(() => result.current.showNotice("Saved"));
  act(() => vi.advanceTimersByTime(4000));
  act(() => result.current.showError("Connection lost"));
  act(() => vi.advanceTimersByTime(10000));
  expect(result.current.notice?.message).toBe("Connection lost");
  act(() => result.current.showNotice("Reconnected"));
  act(() => vi.advanceTimersByTime(4000));
  act(() => result.current.showNotice("Exported"));
  act(() => vi.advanceTimersByTime(1000));
  expect(result.current.notice?.message).toBe("Exported");
});
