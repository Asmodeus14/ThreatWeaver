import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./styles/tokens.css";
import "./styles/app.css";
import { App } from "./App";

// Apply the stored theme before the first render (dark unless the viewer chose otherwise).
try {
  const t = localStorage.getItem("tw-theme") ?? "dark";
  if (t === "dark" || t === "light") document.documentElement.setAttribute("data-theme", t);
} catch {
  document.documentElement.setAttribute("data-theme", "dark");
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
