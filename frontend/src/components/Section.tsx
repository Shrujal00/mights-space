import type { ReactNode } from "react";

interface Props {
  /* Written from the reader's side of the screen: what the section tells them,
   * not what subsystem produced it. */
  title: string;
  count?: number;
  children: ReactNode;
}

export default function Section({ title, count, children }: Props) {
  return (
    <section className="sec">
      <div className="sec__head">
        <h2 className="label">{title}</h2>
        {count !== undefined && <span className="sec__count">{count}</span>}
      </div>
      {children}
    </section>
  );
}
