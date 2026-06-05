import { useCallback, useEffect, useRef, useState } from "react";

/**
 * usePoll — centralised polling hook.
 *
 * Behaviour:
 *  - Fetches immediately on mount, then every `intervalMs`.
 *  - Pauses while `document.hidden` (tab not visible); resumes + refetches immediately
 *    when the tab becomes visible again.
 *  - `error` is cleared back to null on the next successful response.
 *  - `loading` is true until the very first request settles (success or error).
 *  - `refresh()` triggers an immediate out-of-band fetch without resetting the interval.
 *  - Cleans up the interval and the visibilitychange listener on unmount.
 *  - Stale-response guard: each fetch is tagged with a monotonically increasing counter;
 *    responses from earlier fetches are discarded if a newer one has already landed.
 *  - Mounted guard: setState is never called after the component unmounts.
 */
export function usePoll<T>(
  fetcher: () => Promise<T>,
  intervalMs: number,
  deps: unknown[] = [],
): { data: T | null; error: string | null; loading: boolean; refresh: () => void } {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  // Always hold the latest fetcher without it being a dep of the effect.
  const fetcherRef = useRef(fetcher);
  useEffect(() => { fetcherRef.current = fetcher; });

  // Mounted guard — never call setState after unmount.
  const mountedRef = useRef(true);
  useEffect(() => { mountedRef.current = true; return () => { mountedRef.current = false; }; }, []);

  // Stale-response guard — monotonically increasing fetch sequence.
  const seqRef = useRef(0);

  // Stable callback that runs one fetch and updates state only when:
  //   (a) the component is still mounted, AND
  //   (b) this fetch's sequence number is still the latest.
  const doFetch = useCallback(() => {
    const seq = ++seqRef.current;
    fetcherRef.current()
      .then((result) => {
        if (!mountedRef.current || seq !== seqRef.current) return;
        setData(result);
        setError(null);   // clear any previous error on success
        setLoading(false);
      })
      .catch((err: unknown) => {
        if (!mountedRef.current || seq !== seqRef.current) return;
        const msg = err instanceof Error ? err.message : String(err);
        setError(msg);
        setLoading(false);
      });
  }, []); // stable — depends only on refs

  // Core polling effect: re-runs when intervalMs or user-supplied deps change.
  // `doFetch` is stable (refs only); intervalMs + caller deps are spread manually
  // so a config change re-sets-up the interval. exhaustive-deps is disabled because
  // the lint rule can't see that doFetch is intentionally ref-stable.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => {
    // Signal in-flight on (re)setup only — i.e. mount or a deps/intervalMs change —
    // so a switched query shows loading. NOT inside doFetch, which would flip
    // loading true on every interval tick and make panels flicker.
    setLoading(true);

    // Don't start a new interval if the tab is hidden — fetch when it becomes visible.
    if (!document.hidden) {
      doFetch();
    }

    let timer: ReturnType<typeof setInterval> | null = null;

    const startInterval = () => {
      if (timer !== null) clearInterval(timer);
      timer = setInterval(() => {
        // Skip the tick while hidden — the visibility handler will catch the resume.
        if (!document.hidden) doFetch();
      }, intervalMs);
    };

    const onVisibilityChange = () => {
      if (document.hidden) {
        // Tab hidden — tear down the interval to avoid firing while invisible.
        if (timer !== null) { clearInterval(timer); timer = null; }
      } else {
        // Tab visible again — refetch immediately then resume the interval.
        doFetch();
        startInterval();
      }
    };

    // Start the interval immediately (only if tab is visible).
    if (!document.hidden) startInterval();

    document.addEventListener("visibilitychange", onVisibilityChange);

    return () => {
      if (timer !== null) clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisibilityChange);
    };
    // deps spread intentionally: intervalMs + caller-supplied deps drive re-setup.
    // doFetch is stable (only refs), so it won't trigger spurious re-runs.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [intervalMs, doFetch, ...deps]);

  // refresh: out-of-band immediate fetch that doesn't touch the running interval.
  const refresh = useCallback(() => { doFetch(); }, [doFetch]);

  return { data, error, loading, refresh };
}
