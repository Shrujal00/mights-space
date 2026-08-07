import { useMemo } from "react";
import { formatOffset, formatBytes, formatRecordCount, describeObservation } from "../api/format";
import type { BehaviorEvent, ExfiltrationFinding } from "../api/types";
import "./BehaviorTimeline.css";

interface Props {
  events: BehaviorEvent[];
  exfiltration: ExfiltrationFinding[];
  timed: boolean;
  coverage: string;
}

export default function BehaviorTimeline({ events, exfiltration, timed, coverage }: Props) {
  const groupIndices = useMemo(() => {
    const groups = new Set<number>();
    for (let i = 0; i < events.length; i++) {
      if (events[i].category === "data-access") {
        let foundNetwork = false;
        let j = i + 1;
        for (; j <= i + 3 && j < events.length; j++) {
          if (events[j].category === "network") {
            foundNetwork = true;
            break;
          }
        }
        if (foundNetwork) {
          for (let k = i; k <= j; k++) {
            groups.add(k);
          }
        }
      }
    }
    return groups;
  }, [events]);

  return (
    <div className="behavior-timeline">
      {coverage && (
        <div className="bt-coverage">
          {coverage}
        </div>
      )}
      {!timed && events.length > 0 && (
        <div className="bt-notice">
          Events are in execution order; timing was not recorded.
        </div>
      )}
      
      <div className="bt-events">
        {events.map((ev, i) => {
          const isGrouped = groupIndices.has(i);
          const isGroupStart = isGrouped && !groupIndices.has(i - 1);
          const isGroupEnd = isGrouped && !groupIndices.has(i + 1);
          
          let spineClass = "bt-spine";
          if (isGrouped) {
            spineClass += " bt-spine--active";
            if (isGroupStart) spineClass += " bt-spine--start";
            if (isGroupEnd) spineClass += " bt-spine--end";
            if (isGroupStart && isGroupEnd) spineClass += " bt-spine--single";
          }

          const recordCountDisplay = formatRecordCount(ev.record_count);
          const sizeDisplay = formatBytes(ev.size_bytes);
          
          return (
            <div key={i} className="bt-row">
              <div className="bt-time mono">
                {timed ? formatOffset(ev.offset_ms) : (i + 1).toString()}
              </div>
              
              <div className="bt-gutter">
                <div className={spineClass}></div>
              </div>
              
              <div className="bt-content">
                <div className="bt-action">{describeObservation(ev)}</div>
                <div className="bt-meta">
                  <span className="bt-category mono">{ev.category}</span>
                  {ev.detail && <span className="bt-detail">{ev.detail}</span>}
                </div>
                {recordCountDisplay && <div className="bt-record-count">{recordCountDisplay}</div>}
                {sizeDisplay && <div className="bt-size mono">{sizeDisplay}</div>}
              </div>
            </div>
          );
        })}
      </div>

      {exfiltration.length > 0 && (
        <div className="bt-exf-list">
          {exfiltration.map((ex, i) => (
            <div key={i} className="bt-exf-item notice">
              <div className="bt-exf-what">{ex.what}</div>
              <div className="bt-exf-where mono">{ex.where}</div>
              {ex.gap_ms !== null && (
                <div className="bt-exf-gap">{(ex.gap_ms / 1000).toFixed(1)}s later</div>
              )}
              <div className={`bt-exf-conf bt-exf-conf--${ex.confidence}`}>
                {ex.confidence}
              </div>
              {ex.bytes_sent !== null && (
                <div className="bt-exf-bytes mono">{formatBytes(ex.bytes_sent)}</div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
