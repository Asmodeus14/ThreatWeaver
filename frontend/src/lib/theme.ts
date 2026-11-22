import { useEffect, useState } from "react";

export type Theme = "dark" | "light" | "system";
const KEY = "tw-theme";

function read(): Theme {
  try {
    const v = localStorage.getItem(KEY);
    return v === "light" || v === "system" || v === "dark" ? v : "dark";
  } catch {
    return "dark";
  }
}

/** Dark is the default; "system" follows the OS. Stored per browser only. */
export function useTheme(): [Theme, (t: Theme) => void] {
  const [theme, setTheme] = useState<Theme>(read);
  useEffect(() => {
    const root = document.documentElement;
    if (theme === "system") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", theme);
    try {
      localStorage.setItem(KEY, theme);
    } catch {
      /* storage unavailable: the theme still applies for this session */
    }
  }, [theme]);
  return [theme, setTheme];
}

export const nextTheme = (t: Theme): Theme => (t === "dark" ? "light" : t === "light" ? "system" : "dark");
