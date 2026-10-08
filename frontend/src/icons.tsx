// icons.tsx — small inline SVG icon set (stroke follows currentColor so
// they inherit nav active/inactive colors). No emoji, no icon dependency.

type P = { size?: number };
const base = (size: number) => ({
  width: size,
  height: size,
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.8,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
});

export const IconGrid = ({ size = 16 }: P) => (
  <svg {...base(size)}><rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" /><rect x="3" y="14" width="7" height="7" /><rect x="14" y="14" width="7" height="7" /></svg>
);
export const IconShield = ({ size = 16 }: P) => (
  <svg {...base(size)}><path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z" /></svg>
);
export const IconLog = ({ size = 16 }: P) => (
  <svg {...base(size)}><path d="M4 4h16v16H4z" /><path d="M8 8h8M8 12h8M8 16h5" /></svg>
);
export const IconSearch = ({ size = 16 }: P) => (
  <svg {...base(size)}><circle cx="11" cy="11" r="7" /><path d="M20 20l-3.5-3.5" /></svg>
);
export const IconUsers = ({ size = 16 }: P) => (
  <svg {...base(size)}><circle cx="9" cy="8" r="3.5" /><path d="M3 20c0-3.3 2.7-6 6-6s6 2.7 6 6" /><path d="M16 6a3 3 0 010 6" /></svg>
);
export const IconWebhook = ({ size = 16 }: P) => (
  <svg {...base(size)}><circle cx="6" cy="12" r="2.5" /><circle cx="18" cy="6" r="2.5" /><circle cx="18" cy="18" r="2.5" /><path d="M8.2 10.8l7.6-3.6M8.2 13.2l7.6 3.6" /></svg>
);
export const IconChart = ({ size = 16 }: P) => (
  <svg {...base(size)}><path d="M4 20V4M4 20h16" /><path d="M8 16v-4M12 16V8M16 16v-6" /></svg>
);
export const IconSave = ({ size = 16 }: P) => (
  <svg {...base(size)}><path d="M5 3h11l3 3v15H5z" /><path d="M8 3v6h7V3M8 21v-7h8v7" /></svg>
);
export const IconLock = ({ size = 16 }: P) => (
  <svg {...base(size)}><rect x="4" y="10" width="16" height="11" rx="2" /><path d="M8 10V7a4 4 0 018 0v3" /></svg>
);
export const IconTerminal = ({ size = 16 }: P) => (
  <svg {...base(size)}><rect x="3" y="4" width="18" height="16" rx="2" /><path d="M7 9l3 3-3 3M13 15h4" /></svg>
);
export const IconPulse = ({ size = 16 }: P) => (
  <svg {...base(size)}><path d="M3 12h4l2-6 4 12 2-6h6" /></svg>
);