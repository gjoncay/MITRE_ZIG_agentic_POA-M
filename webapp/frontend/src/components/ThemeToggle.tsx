import { useEffect, useState } from "react";

type Theme = "light" | "dark";

const STORAGE_KEY = "csdh-theme";

function readStoredTheme(): Theme {
  if (typeof localStorage === "undefined") return "light";
  return localStorage.getItem(STORAGE_KEY) === "dark" ? "dark" : "light";
}

function applyTheme(theme: Theme) {
  const root = document.documentElement;
  if (theme === "dark") root.setAttribute("data-theme", "dark");
  else root.removeAttribute("data-theme");
}

/** Light/dark theme toggle. Persists via localStorage and sets data-theme on <html>. */
export default function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>(() => readStoredTheme());

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  function toggle() {
    setTheme((prev) => {
      const next: Theme = prev === "dark" ? "light" : "dark";
      if (typeof localStorage !== "undefined") localStorage.setItem(STORAGE_KEY, next);
      return next;
    });
  }

  return (
    <button
      type="button"
      onClick={toggle}
      className="rounded-md border px-3 py-1.5 text-sm font-medium transition-colors"
      style={{
        borderColor: "var(--border-default)",
        color: "var(--text-secondary)",
        backgroundColor: "var(--bg-surface)",
      }}
      aria-label="Toggle color theme"
      title="Toggle light/dark theme"
    >
      {theme === "dark" ? "Dark" : "Light"}
    </button>
  );
}
