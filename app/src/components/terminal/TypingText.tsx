"use client";

import { useEffect, useState } from "react";

type TypingTextProps = {
  text: string;
  speedMs?: number;
  startDelayMs?: number;
  className?: string;
  cursor?: boolean;
  onDone?: () => void;
};

export function TypingText({
  text,
  speedMs = 22,
  startDelayMs = 0,
  className = "",
  cursor = true,
  onDone,
}: TypingTextProps) {
  const [visibleChars, setVisibleChars] = useState(0);

  useEffect(() => {
    let charIndex = 0;
    let intervalId: ReturnType<typeof setInterval>;

    const startTimeout = setTimeout(() => {
      setVisibleChars(0);
      intervalId = setInterval(() => {
        charIndex += 1;
        setVisibleChars(charIndex);
        if (charIndex >= text.length) {
          clearInterval(intervalId);
          onDone?.();
        }
      }, speedMs);
    }, startDelayMs);

    return () => {
      clearTimeout(startTimeout);
      clearInterval(intervalId);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [text, speedMs, startDelayMs]);

  return (
    <span className={className}>
      {text.slice(0, visibleChars)}
      {cursor && <span className="term-cursor" aria-hidden="true" />}
    </span>
  );
}
