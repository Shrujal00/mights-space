import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { api } from "../api/client";
import type { Health } from "../api/types";

export const NAV_ITEMS = [
  { name: "Dashboard", path: "/", hash: "" },
  { name: "Analysis Center", path: "/", hash: "#analyses" },
  { name: "Static Analysis", path: "/", hash: "#static" },
  { name: "Dynamic Sandbox", path: "/", hash: "#sandbox" },
  { name: "Android Analysis", path: "/", hash: "#android" },
  { name: "Windows Analysis", path: "/", hash: "#windows" },
  { name: "Reports", path: "/", hash: "#reports" },
  { name: "IOC Feed", path: "/", hash: "#iocs" },
  { name: "Threat Intelligence", path: "/", hash: "#threats" },
  { name: "Settings", path: "/", hash: "#settings" },
  { name: "Help & Docs", path: "/", hash: "#docs" },
];

export default function Sidebar() {
  const location = useLocation();
  const [health, setHealth] = useState<Health | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .health()
      .then((val) => {
        if (!cancelled) setHealth(val);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  const currentHash = location.hash;

  return (
    <aside className="side">
      <div className="side__head">
        <Link to="/" className="side__brand">
          <span className="side__crest label">Surat Cyber Police</span>
          <span className="side__title">Forensics Hub</span>
        </Link>
      </div>

      <nav className="side__nav">
        {NAV_ITEMS.map((item) => {
          const isDashboard = item.hash === "" && location.pathname === "/" && !currentHash;
          const isHashActive = item.hash !== "" && currentHash === item.hash;
          const isActive = isDashboard || isHashActive;

          return (
            <Link
              key={item.name}
              to={`${item.path}${item.hash}`}
              className={`side__link ${isActive ? "side__link--active" : ""}`}
            >
              <span className="side__link-text">{item.name}</span>
            </Link>
          );
        })}
      </nav>

      {health && (
        <div className="side__foot">
          <div className="side__status">
            <span
              className={
                health.offline_mode ? "rail__ring" : "rail__ring rail__ring--on"
              }
              aria-hidden="true"
            />
            <span className="label">
              {health.offline_mode ? "Air-Gapped" : "Connected"}
            </span>
          </div>

          <div className="side__meta label" title={rulesTitle(health)}>
            {health.yara_rules_loaded.toLocaleString()} signatures
          </div>
        </div>
      )}
    </aside>
  );
}

function rulesTitle(health: Health): string {
  if (health.yara_rules_skipped === 0) {
    return "All signature files loaded.";
  }
  return `${health.yara_rules_skipped} signature file(s) could not be loaded.`;
}
