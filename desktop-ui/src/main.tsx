import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { About } from "./About";
import { startTheme } from "./theme";

// WebKitGTK's native controls need explicit dark styling on Linux.
if (/\bLinux\b/.test(navigator.userAgent)) {
  document.documentElement.dataset.platform = "linux";
}

// Apply the saved appearance (System follows macOS light/dark).
startTheme();

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    {window.location.hash === "#about" ? <About /> : <App />}
  </React.StrictMode>,
);
