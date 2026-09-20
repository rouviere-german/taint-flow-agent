"""Small statistics helpers for the benchmark: rates with Wilson score intervals."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, final

__all__ = ["Rate", "wilson_interval"]

_Z95 = 1.959963984540054


def wilson_interval(successes: int, trials: int, *, z: float = _Z95) -> tuple[float, float]:
    """Wilson (1927) score interval for a binomial proportion; ``(0, 1)`` when ``trials`` is 0.

    Unlike the Wald interval it never leaves ``[0, 1]`` and stays informative at 0 or n
    successes, which is exactly where an attack-success rate of 0 sits.
    """
    if trials < 0 or successes < 0 or successes > trials:
        raise ValueError("successes must be between 0 and trials")
    if trials == 0:
        return 0.0, 1.0
    p = successes / trials
    z2 = z * z
    denominator = 1.0 + z2 / trials
    centre = (p + z2 / (2.0 * trials)) / denominator
    spread = z * math.sqrt(p * (1.0 - p) / trials + z2 / (4.0 * trials * trials)) / denominator
    # The closed form is exact in real arithmetic but not in binary floating point: at 0 or n
    # successes it can land a few ULPs off the estimate (0 successes gave 1.7e-18, n successes
    # gave 1 - 1.1e-16). Clamping to [0, 1] and to the estimate keeps the two invariants callers
    # rely on -- the interval is a subset of [0, 1] and contains p -- exact at the boundaries.
    low = min(max(0.0, centre - spread), p)
    high = max(min(1.0, centre + spread), p)
    return low, high


@final
@dataclass(frozen=True, slots=True)
class Rate:
    successes: int
    trials: int

    @property
    def value(self) -> float:
        return self.successes / self.trials if self.trials else 0.0

    @property
    def interval(self) -> tuple[float, float]:
        return wilson_interval(self.successes, self.trials)

    def to_json(self) -> dict[str, Any]:
        low, high = self.interval
        return {
            "successes": self.successes,
            "trials": self.trials,
            "rate": round(self.value, 4),
            "ci95": [round(low, 4), round(high, 4)],
        }

    def __str__(self) -> str:
        low, high = self.interval
        return f"{self.value:.1%} ({self.successes}/{self.trials}, 95% CI {low:.1%}-{high:.1%})"
