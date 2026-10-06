import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, test } from "vitest";
import { RuntimeCleanupNotice } from "../src/RuntimeCleanupNotice";

afterEach(cleanup);

test("uncertain retention remains visible with details and disappears after successful retry", async () => {
  const report = { warnings: [{ path: "/private/runtime/old", message: "Cannot inspect process 123 to verify this runtime is unused." }] };
  const { rerender } = render(<RuntimeCleanupNotice report={report} />);
  expect(screen.getByRole("alert")).toBeTruthy();
  await userEvent.setup().click(screen.getByText(/App runtime cleanup needs attention/));
  expect(screen.getByText(report.warnings[0].message)).toBeTruthy();
  expect(screen.getByText(report.warnings[0].path)).toBeTruthy();
  rerender(<RuntimeCleanupNotice report={{ warnings: [] }} />);
  expect(screen.queryByRole("alert")).toBeNull();
});
