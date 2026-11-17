import type { Config } from "tailwindcss";
const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg:    "#0b0d12",
        panel: "#11141b",
        line:  "#1c212c",
        soft:  "#242b38",
        ink:   "#d9dde3",
        mute:  "#8a93a3",
        acc:   "#7dd3fc",   // cyan accent
        warn:  "#f59e0b",
        err:   "#ef4444",
        ok:    "#22c55e",
      },
      fontFamily: {
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      },
    },
  },
  plugins: [],
};
export default config;
