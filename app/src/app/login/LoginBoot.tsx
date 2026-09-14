"use client";

import { useEffect, useRef, useState, type ReactNode } from "react";

// Sequência de classes e o delay (ms) em que cada uma entra, replicando o
// protótipo de animação de boot fornecido pelo usuário. Cada classe some
// acionar uma transição CSS definida em globals.css (.sentinela-boot.*).
const SEQUENCE: Array<[number, string]> = [
  [0, "draw-outline"],
  [600, "flash-corners"],
  [1000, "draw-cross"],
  [1600, "pulse-dot"],
  [1800, "typing"],
  [2800, "show-tagline"],
  [3100, "done"],
];

const SKIPPED_CLASSES = [
  "draw-outline",
  "flash-corners",
  "draw-cross",
  "pulse-dot",
  "typed",
  "show-tagline",
  "done",
];

export function LoginBoot({ children }: { children: ReactNode }) {
  const [classes, setClasses] = useState<Set<string>>(new Set());
  const timersRef = useRef<ReturnType<typeof setTimeout>[]>([]);
  const skippedRef = useRef(false);

  useEffect(() => {
    const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    function skip() {
      if (skippedRef.current) return;
      skippedRef.current = true;
      timersRef.current.forEach(clearTimeout);
      timersRef.current = [];
      setClasses(new Set(SKIPPED_CLASSES));
      document.removeEventListener("click", skip);
      document.removeEventListener("keydown", skip);
    }

    if (prefersReducedMotion) {
      skip();
      return;
    }

    timersRef.current = SEQUENCE.map(([delay, className]) =>
      setTimeout(() => setClasses((prev) => new Set(prev).add(className)), delay),
    );
    document.addEventListener("click", skip);
    document.addEventListener("keydown", skip);

    return () => {
      timersRef.current.forEach(clearTimeout);
      document.removeEventListener("click", skip);
      document.removeEventListener("keydown", skip);
    };
  }, []);

  const containerClass = ["sentinela-boot", ...Array.from(classes)].join(" ");

  return (
    <div className={containerClass}>
      <div className="logo-wrap">
        <svg className="logo-svg" viewBox="0 0 200 200" role="img" aria-label="Sentinela">
          <rect className="logo-outline" x="8" y="8" width="184" height="184" rx="16" />

          <polyline className="corner corner-1" points="28,52 28,28 52,28" />
          <polyline className="corner corner-2" points="148,28 172,28 172,52" />
          <polyline className="corner corner-3" points="28,148 28,172 52,172" />
          <polyline className="corner corner-4" points="172,148 172,172 148,172" />

          <g className="cross-group">
            <circle cx="100" cy="100" r="40" />
            <line x1="100" y1="42" x2="100" y2="60" />
            <line x1="100" y1="140" x2="100" y2="158" />
            <line x1="42" y1="100" x2="60" y2="100" />
            <line x1="140" y1="100" x2="158" y2="100" />
          </g>
          <circle className="dot-crit" cx="100" cy="100" r="6" />
        </svg>

        <div className="wordmark">
          <span className="name-text">sentinela</span>
          <span className="cursor" />
        </div>
        <div className="tagline">PENTEST &amp; BUG BOUNTY</div>
      </div>

      <div className="login-reveal">{children}</div>

      <div className="skip-hint">clique ou pressione qualquer tecla para pular a animação</div>
    </div>
  );
}
