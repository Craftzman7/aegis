import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { App } from "./App";
import { LiveProvider } from "./live/LiveProvider";
import "./index.css";

const qc = new QueryClient({ defaultOptions: { queries: { staleTime: 5_000, retry: 1, refetchOnWindowFocus: true } } });

async function boot() {
  if (import.meta.env.VITE_MOCK) {
    const { installMockApi } = await import("./mock/install");
    installMockApi();
  }
  createRoot(document.getElementById("root") as HTMLElement).render(
    <StrictMode>
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <LiveProvider><App /></LiveProvider>
        </BrowserRouter>
      </QueryClientProvider>
    </StrictMode>,
  );
}
void boot();
