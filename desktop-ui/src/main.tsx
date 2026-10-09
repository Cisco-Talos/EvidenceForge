import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { About } from "./About";

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    {window.location.hash === "#about" ? <About /> : <App />}
  </React.StrictMode>,
);
