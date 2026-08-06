import { Route, Routes, useLocation } from "react-router-dom";

import Sidebar from "./components/Sidebar";
import Dashboard from "./pages/Dashboard";
import Report from "./pages/Report";

export default function App() {
  const location = useLocation();
  const isReportPage = location.pathname.startsWith("/samples/");

  return (
    <div className="shell">
      <Sidebar />
      <div className="shell__main">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/samples/:id" element={<Report />} />
          <Route path="*" element={<Dashboard />} />
        </Routes>
        {/* Whether a file was run is a fact about one report, and only the
          * report knows it — so that claim is made there, per sample. A blanket
          * "static analysis only" here would be false for every detonated
          * sample. What is stated globally is the one thing always true. */}
        {!isReportPage && (
          <footer className="foot page">
            No file is ever described as safe · An absence of findings is not a
            clearance
          </footer>
        )}
      </div>
    </div>
  );
}
