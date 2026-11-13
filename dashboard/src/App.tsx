import { Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { Approvals } from "./pages/Approvals";
import { Audit } from "./pages/Audit";
import { HostDetail } from "./pages/HostDetail";
import { Hosts } from "./pages/Hosts";
import { IncidentDetail } from "./pages/IncidentDetail";
import { Incidents } from "./pages/Incidents";
import { Overview } from "./pages/Overview";
import { Rules } from "./pages/Rules";
import { Settings } from "./pages/Settings";

export function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Overview />} />
        <Route path="incidents" element={<Incidents />} />
        <Route path="incidents/:id" element={<IncidentDetail />} />
        <Route path="approvals" element={<Approvals />} />
        <Route path="hosts" element={<Hosts />} />
        <Route path="hosts/:id" element={<HostDetail />} />
        <Route path="rules" element={<Rules />} />
        <Route path="audit" element={<Audit />} />
        <Route path="settings" element={<Settings />} />
        <Route path="*" element={<div className="p-4 text-muted">Not found.</div>} />
      </Route>
    </Routes>
  );
}
