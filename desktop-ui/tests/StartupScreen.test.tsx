import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, test } from "vitest";
import "@testing-library/jest-dom/vitest";
import { StartupScreen } from "../src/StartupScreen";

afterEach(cleanup);

test("first setup displays actual extraction progress and update stages can be indeterminate", () => {
  const view = render(<StartupScreen error={null} progress={{ title: "Doing first-time setup", detail: "Installing your private runtime…", percent: 35 }} />);
  expect(screen.getByRole("heading")).toHaveTextContent("Doing first-time setup");
  expect(screen.getByRole("progressbar")).toHaveAttribute("value", "35");
  view.rerender(<StartupScreen error={null} progress={{ title: "Updating Studio", detail: "Verifying the bundled runtime…", percent: null }} />);
  expect(screen.getByRole("heading")).toHaveTextContent("Updating Studio");
  expect(screen.getByRole("progressbar")).not.toHaveAttribute("value");
  view.rerender(<StartupScreen error="Cannot open private storage" />);
  expect(screen.getByRole("alert")).toHaveTextContent("Cannot open private storage");
  expect(screen.queryByRole("progressbar")).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
});
