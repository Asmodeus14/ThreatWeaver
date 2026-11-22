import type { ReactNode } from "react";

export function Loading({ lines = 3 }: { lines?: number }) {
  return (
    <div className="state" aria-busy="true" aria-live="polite">
      {Array.from({ length: lines }).map((_, i) => (
        <div key={i} className="skeleton" style={{ width: `${70 - i * 15}%` }} />
      ))}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="state error" role="alert">
      <strong>Could not load this section</strong>
      <span>{message}</span>
      {onRetry && <button onClick={onRetry}>Try again</button>}
    </div>
  );
}

export function Empty({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="state">
      <strong>{title}</strong>
      {children && <span>{children}</span>}
      {action}
    </div>
  );
}

/** Renders loading / error / empty / content for a useApi() result. */
export function Async<T>({
  state,
  empty,
  children,
}: {
  state: { data: T | null; error: string | null; loading: boolean; reload: () => void };
  empty?: (data: T) => ReactNode | null;
  children: (data: T) => ReactNode;
}) {
  if (state.error) return <ErrorState message={state.error} onRetry={state.reload} />;
  if (state.loading && !state.data) return <Loading />;
  if (!state.data) return null;
  const e = empty?.(state.data);
  return <>{e ?? children(state.data)}</>;
}
