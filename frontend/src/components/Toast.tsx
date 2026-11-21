import { createContext, ReactNode, useCallback, useContext, useState } from "react";

type Toast = { id: number; text: string; error?: boolean };
const Ctx = createContext<(text: string, error?: boolean) => void>(() => {});

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toast, setToast] = useState<Toast | null>(null);
  const show = useCallback((text: string, error = false) => {
    const id = Date.now();
    setToast({ id, text, error });
    window.setTimeout(() => setToast((t) => (t && t.id === id ? null : t)), error ? 7000 : 3500);
  }, []);
  return (
    <Ctx.Provider value={show}>
      {children}
      <div aria-live="polite" role="status">
        {toast && <div className={`toast${toast.error ? " error" : ""}`}>{toast.text}</div>}
      </div>
    </Ctx.Provider>
  );
}

export const useToast = () => useContext(Ctx);
