import "@testing-library/jest-dom/vitest";
import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { JobDiagnostics } from "../src/JobDiagnostics";
import type { StudioApi, StudioJob } from "../src/api";

afterEach(cleanup);

test("log refresh preserves the preview through requests and failures without adding a job badge", async () => {
  const log = { available: true, log_path: "/run/generation.log", tail: "Existing log contents", message: null, truncated: false };
  let finish!: (value: typeof log) => void;
  let fail!: (error: Error) => void;
  const request = vi.fn(async () => log);
  const props = { job: { id: "one", status: "running", kind: "generation" } as StudioJob, api: { request } as unknown as StudioApi, onError: vi.fn(), requestedLog: true };
  const view = render(<JobDiagnostics {...props} />);
  await screen.findByText(log.tail);
  request.mockImplementation(() => new Promise((resolve, reject) => { finish = resolve; fail = reject; }));
  view.rerender(<JobDiagnostics {...props} refreshVersion={1} />);
  expect(screen.getByText("Refreshing log…")).toBeVisible();
  expect(screen.getByText(log.tail)).toBeVisible();
  await act(async () => fail(new Error("Log file is temporarily unreadable")));
  expect(screen.getByRole("alert")).toHaveTextContent("Log file is temporarily unreadable");
  expect(screen.getByText("Previous log preview is shown below.")).toBeVisible();
  view.rerender(<JobDiagnostics {...props} refreshVersion={2} />);
  expect(screen.queryByRole("alert")).toBeNull();
  await act(async () => finish(log));
  expect(screen.getByRole("status")).toHaveTextContent("Updated");
  expect(view.container.querySelector(".status")).toBeNull();
  view.rerender(<JobDiagnostics {...props} job={{ ...props.job, id: "two" }} />);
  expect(screen.queryByText(log.tail)).toBeNull();
  await act(async () => finish({ ...log, tail: "Second job log" }));
  expect(screen.getByText("Second job log")).toBeVisible();
});
