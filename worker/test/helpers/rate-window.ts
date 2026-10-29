/**
 * Rate budgets are fixed one-minute windows keyed to the wall clock. A burst that
 * straddles a minute boundary, which a CPU-starved run can stretch it into, starts a
 * fresh budget and never reaches the limit. Waiting out the tail of the current
 * minute makes the burst land in one window whatever the machine's speed.
 */
export async function awaitRateWindowHeadroom(windowMs = 60_000, headroomMs = 15_000): Promise<void> {
  const into = Date.now() % windowMs;
  if (into > windowMs - headroomMs) await new Promise((r) => setTimeout(r, windowMs - into + 50));
}
