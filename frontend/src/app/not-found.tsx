import Link from "next/link";

export default function NotFound() {
  return (
    <div className="h-full grid place-items-center px-6">
      <div className="text-center max-w-md">
        <div className="mono text-[11px] tracking-[0.1em] uppercase text-ink-3">404</div>
        <h1 className="text-[23px] font-semibold tracking-[-0.025em] mt-2">This page does not exist</h1>
        <p className="text-[12.5px] text-ink-2 mt-2">
          The link may be stale, or the record may belong to a different company than the one you have active.
        </p>
        <Link
          href="/"
          className="inline-flex items-center h-[30px] px-3 mt-5 rounded-md border border-rule-2 bg-surface text-[12.5px] font-medium hover:bg-surface-2"
        >
          Back to Overview
        </Link>
      </div>
    </div>
  );
}
