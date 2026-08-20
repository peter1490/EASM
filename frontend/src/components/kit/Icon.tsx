/**
 * The icon set. Stroke-drawn on a 16px grid, one path each, so an icon scales
 * and recolours with `currentColor` like any other glyph.
 *
 * The previous build used emoji for navigation and tab bars; they rendered
 * differently on every platform and could not take a colour.
 */

export const ICON_PATHS = {
  search: "M11.6 11.6 14.2 14.2M11.6 7.2a4.4 4.4 0 1 1-8.8 0 4.4 4.4 0 0 1 8.8 0Z",
  globe:
    "M8 2.2a5.8 5.8 0 1 0 0 11.6A5.8 5.8 0 0 0 8 2.2Zm0 0c1.6 1.5 2.4 3.5 2.4 5.8s-.8 4.3-2.4 5.8m0-11.6C6.4 3.7 5.6 5.7 5.6 8s.8 4.3 2.4 5.8M2.4 8h11.2",
  server:
    "M3 3.8h10c.6 0 1 .4 1 1v1.6c0 .6-.4 1-1 1H3c-.6 0-1-.4-1-1V4.8c0-.6.4-1 1-1Zm0 4.8h10c.6 0 1 .4 1 1v1.6c0 .6-.4 1-1 1H3c-.6 0-1-.4-1-1V9.6c0-.6.4-1 1-1Z",
  port: "M6.2 2.6 5 13.4M11 2.6 9.8 13.4M2.8 5.8h10.4M2.4 10.2h10.4",
  certificate: "M8 2.2 3.6 4v3.6c0 3 1.8 5.2 4.4 6.2 2.6-1 4.4-3.2 4.4-6.2V4L8 2.2Z",
  shield: "M8 2.2 3.6 4v3.6c0 3 1.8 5.2 4.4 6.2 2.6-1 4.4-3.2 4.4-6.2V4L8 2.2Z",
  shieldCheck:
    "M8 2.2 3.6 4v3.6c0 3 1.8 5.2 4.4 6.2 2.6-1 4.4-3.2 4.4-6.2V4L8 2.2ZM5.9 7.9 7.5 9.6l2.7-3",
  alert: "M8 2.4 1.8 13.2h12.4L8 2.4ZM8 6.6v3M8 11.4h.01",
  play: "M4.6 3.4v9.2l7-4.6-7-4.6Z",
  stop: "M4.4 4.4h7.2v7.2H4.4z",
  clock: "M8 4.4V8l2.4 1.4M8 14a6 6 0 1 0 0-12 6 6 0 0 0 0 12Z",
  ban: "M8 14a6 6 0 1 0 0-12 6 6 0 0 0 0 12ZM3.8 3.8l8.4 8.4",
  plus: "M8 3.4v9.2M3.4 8h9.2",
  minus: "M3.4 8h9.2",
  check: "M3.4 8.4 6.4 11.4l6.2-6.6",
  close: "M4 4l8 8M12 4l-8 8",
  arrowRight: "M3.4 8h9.2m0 0-3.4-3.4M12.6 8l-3.4 3.4",
  arrowUp: "M8 12.4V3.6m0 0L4.4 7.2M8 3.6l3.6 3.6",
  arrowDown: "M8 3.6v8.8m0 0 3.6-3.6M8 12.4 4.4 8.8",
  chevronDown: "m4 6.5 4 3.5 4-3.5",
  chevronRight: "m6.4 4 4 4-4 4",
  download: "M8 2.6v7.2m0 0L5.2 7M8 9.8 10.8 7M2.8 11.4v1.2c0 .4.4.8.8.8h8.8c.4 0 .8-.4.8-.8v-1.2",
  filter: "M2.6 3.4h10.8M4.6 8h6.8M6.4 12.6h3.2",
  sort: "M2.6 3.4h10.8M2.6 8h7.2M2.6 12.6h3.6",
  trash:
    "M3.4 4.6h9.2m-7.4 0V3.4c0-.6.4-1 1-1h3.6c.6 0 1 .4 1 1v1.2m1.4 0v8c0 .6-.4 1-1 1H5c-.6 0-1-.4-1-1v-8",
  copy:
    "M10.6 5.4V4.6c0-.9-.7-1.6-1.6-1.6H4.6c-.9 0-1.6.7-1.6 1.6V9c0 .9.7 1.6 1.6 1.6h.8M7 5.4h5.4c.9 0 1.6.7 1.6 1.6v4.4c0 .9-.7 1.6-1.6 1.6H7c-.9 0-1.6-.7-1.6-1.6V7c0-.9.7-1.6 1.6-1.6Z",
  external:
    "M6.4 3.4h6.2v6.2M12.6 3.4 7 9M12 9.6v2.4c0 .9-.7 1.6-1.6 1.6H5c-.9 0-1.6-.7-1.6-1.6V6.6C3.4 5.7 4.1 5 5 5h2.4",
  bell: "M8 2.2a3.6 3.6 0 0 0-3.6 3.6c0 3-1.2 4-1.2 4h9.6s-1.2-1-1.2-4A3.6 3.6 0 0 0 8 2.2ZM6.7 12.1a1.5 1.5 0 0 0 2.6 0",
  refresh:
    "M13.4 8a5.4 5.4 0 1 1-1.6-3.8M13.4 2.6v3.2h-3.2",
  settings:
    "M8 10.2a2.2 2.2 0 1 0 0-4.4 2.2 2.2 0 0 0 0 4.4M12.9 9.8a1.1 1.1 0 0 0 .22 1.21l.04.04a1.32 1.32 0 1 1-1.87 1.87l-.04-.04a1.1 1.1 0 0 0-1.87.78v.11a1.32 1.32 0 1 1-2.64 0v-.06a1.1 1.1 0 0 0-1.93-.72l-.04.04a1.32 1.32 0 1 1-1.87-1.87l.04-.04a1.1 1.1 0 0 0-.78-1.87h-.11a1.32 1.32 0 1 1 0-2.64h.06a1.1 1.1 0 0 0 .72-1.93l-.04-.04a1.32 1.32 0 1 1 1.87-1.87l.04.04a1.1 1.1 0 0 0 1.87-.78v-.11a1.32 1.32 0 0 1 2.64 0v.06a1.1 1.1 0 0 0 1.87.72l.04-.04a1.32 1.32 0 1 1 1.87 1.87l-.04.04a1.1 1.1 0 0 0 .78 1.87h.11a1.32 1.32 0 1 1 0 2.64h-.06a1.1 1.1 0 0 0-1.01.66Z",
  users:
    "M10.6 13.4v-1.2a2.8 2.8 0 0 0-2.8-2.8H4.6a2.8 2.8 0 0 0-2.8 2.8v1.2M6.2 6.8a2.2 2.2 0 1 0 0-4.4 2.2 2.2 0 0 0 0 4.4M14.2 13.4v-1.2a2.8 2.8 0 0 0-2.1-2.7M10.2 2.5a2.8 2.8 0 0 1 0 5.4",
  building:
    "M2.6 13.4h10.8M4 13.4V3.4c0-.6.4-1 1-1h6c.6 0 1 .4 1 1v10M6.4 5.6h1M8.6 5.6h1M6.4 8h1M8.6 8h1M6.4 10.4h1M8.6 10.4h1",
  tag: "M2.6 7.4V3.4c0-.6.4-1 1-1h4l6 6-5 5-6-6ZM5.6 5.6h.01",
  plug: "M6 2.4v3.2M10 2.4v3.2M4.4 5.6h7.2v2.8a3.6 3.6 0 0 1-7.2 0V5.6ZM8 12v1.6",
  activity: "M1.8 8h2.8l2-4.8 2.8 9.6 2-4.8h2.8",
  seed: "M8 13.8V7.4M8 7.4C8 4.6 5.8 2.4 3 2.4c0 2.8 2.2 5 5 5Zm0 0c0-2.8 2.2-5 5-5 0 2.8-2.2 5-5 5Z",
  dots: "M3.4 8h.01M8 8h.01M12.6 8h.01",
  logout: "M6.2 13.4H3.8c-.6 0-1-.4-1-1V3.6c0-.6.4-1 1-1h2.4M10 11l3-3-3-3M13 8H6",
  key: "M11.6 6.8V5.2a3.6 3.6 0 0 0-7.2 0v1.6M3.8 6.8h8.4c.6 0 1 .4 1 1v5.2c0 .6-.4 1-1 1H3.8c-.6 0-1-.4-1-1V7.8c0-.6.4-1 1-1Z",
  chart: "M2.6 13.4V8M6.2 13.4V3.6M9.8 13.4v-4M13.4 13.4V6",
  link: "M6.8 9.2a2.6 2.6 0 0 0 3.9.3l1.6-1.6a2.6 2.6 0 0 0-3.7-3.7l-.9.9M9.2 6.8a2.6 2.6 0 0 0-3.9-.3L3.7 8.1a2.6 2.6 0 0 0 3.7 3.7l.9-.9",
  eye: "M1.8 8s2.3-4.2 6.2-4.2S14.2 8 14.2 8s-2.3 4.2-6.2 4.2S1.8 8 1.8 8Zm6.2 1.7a1.7 1.7 0 1 0 0-3.4 1.7 1.7 0 0 0 0 3.4Z",
  eyeOff: "M6.6 3.9A5.6 5.6 0 0 1 8 3.8c3.9 0 6.2 4.2 6.2 4.2a11 11 0 0 1-1.8 2.4M4.2 4.6A11 11 0 0 0 1.8 8s2.3 4.2 6.2 4.2c1 0 1.8-.2 2.6-.6M2.6 2.6l10.8 10.8M9.4 9.5a1.7 1.7 0 0 1-2.4-2.4",
} as const;

export type IconName = keyof typeof ICON_PATHS;

export function Icon({
  name,
  size = 14,
  className,
  strokeWidth = 1.4,
}: {
  name: IconName;
  size?: number;
  className?: string;
  strokeWidth?: number;
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      aria-hidden="true"
      className={className}
      style={{ flex: "none" }}
    >
      <path
        d={ICON_PATHS[name]}
        stroke="currentColor"
        strokeWidth={strokeWidth}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

/** Icon for an asset type, so the same shape means the same thing everywhere. */
export function assetIcon(assetType: string | null | undefined): IconName {
  switch (assetType) {
    case "ip":
      return "server";
    case "port":
      return "port";
    case "certificate":
      return "certificate";
    case "organization":
      return "building";
    case "asn":
      return "activity";
    default:
      return "globe";
  }
}
