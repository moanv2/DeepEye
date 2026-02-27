import { useEffect, useState } from "react";

export function useCountUp(
  target: number,
  duration: number,
  trigger: boolean,
  decimals = 0
) {
  const [value, setValue] = useState(0);

  useEffect(() => {
    if (!trigger) return;

    const start = performance.now();

    function update(now: number) {
      const progress = Math.min((now - start) / (duration * 1000), 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      const current = eased * target;
      setValue(
        decimals > 0
          ? parseFloat(current.toFixed(decimals))
          : Math.floor(current)
      );

      if (progress < 1) {
        requestAnimationFrame(update);
      }
    }

    requestAnimationFrame(update);
  }, [trigger, target, duration, decimals]);

  return value;
}
