/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        void: "#07090a", // deep terminal black
        surface: "#0b0f10", // panel base
        line: "#16221f", // hairline borders
        amber: "#ffb000", // phosphor — system / primary
        amberdim: "#7a5600",
        redteam: "#ff414d",
        blueteam: "#3ec6ff",
        purple: "#c084fc",
        phos: "#6ee7a8", // green telemetry
        dim: "#5d6b67",
      },
      fontFamily: {
        display: ['"Chakra Petch"', "ui-monospace", "monospace"],
        mono: ['"IBM Plex Mono"', "ui-monospace", "monospace"],
      },
      boxShadow: {
        glow: "0 0 0 1px rgba(255,176,0,0.15), 0 0 18px -6px rgba(255,176,0,0.35)",
      },
      keyframes: {
        boot: {
          "0%": { opacity: "0", transform: "translateY(6px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        blink: { "0%,49%": { opacity: "1" }, "50%,100%": { opacity: "0.15" } },
        flicker: {
          "0%,100%": { opacity: "1" },
          "92%": { opacity: "1" },
          "93%": { opacity: "0.7" },
          "94%": { opacity: "1" },
        },
      },
      animation: {
        boot: "boot 0.45s cubic-bezier(0.2,0.8,0.2,1) both",
        blink: "blink 1.1s steps(1) infinite",
        flicker: "flicker 6s linear infinite",
      },
    },
  },
  plugins: [],
};
