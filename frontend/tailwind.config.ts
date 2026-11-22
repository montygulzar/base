import type { Config } from "tailwindcss";
const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg:    "#0a0a0b",
        panel: "#131316",
        line:  "#232327",
        soft:  "#1b1b1f",
        ink:   "#f5f5f6",
        mute:  "#8a8a92",
        dim:   "#55555c",
        acc:   "#ff3b3b",   // red accent, used sparingly
        acc2:  "#ff5c5c",
        warn:  "#f59e0b",
        ok:    "#22c55e",
        err:   "#ff3b3b",
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "-apple-system", "Segoe UI", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      },
    },
  },
  plugins: [],
};
export default config;
