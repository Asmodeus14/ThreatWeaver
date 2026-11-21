import { useEffect, useState } from "react";

export interface Route {
  page: string;
  params: URLSearchParams;
}

function parse(): Route {
  const raw = window.location.hash.replace(/^#\/?/, "");
  const [page, query = ""] = raw.split("?");
  return { page: page || "overview", params: new URLSearchParams(query) };
}

export function useRoute(): Route {
  const [route, setRoute] = useState<Route>(parse);
  useEffect(() => {
    const on = () => setRoute(parse());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return route;
}

export function go(page: string, params?: Record<string, string>) {
  const q = params ? `?${new URLSearchParams(params).toString()}` : "";
  window.location.hash = `#/${page}${q}`;
}
