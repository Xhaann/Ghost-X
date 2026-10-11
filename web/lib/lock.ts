export const deviceLockName = "ghostx-device";

export function requestDeviceLock(
  signal: AbortSignal,
  waiting: () => void = () => {},
  notice = 250,
): Promise<() => void> {
  const locks = typeof navigator === "undefined" ? undefined : navigator.locks;
  if (!locks) {
    return Promise.reject(new Error("unavailable"));
  }
  return new Promise((resolve, reject) => {
    const hold = () => new Promise<void>((release) => resolve(release));
    locks
      .request(deviceLockName, { ifAvailable: true }, (lock) => {
        if (lock) {
          return hold();
        }
        if (signal.aborted) {
          reject(signal.reason);
          return undefined;
        }
        const timer = setTimeout(waiting, notice);
        signal.addEventListener("abort", () => clearTimeout(timer), {
          once: true,
        });
        locks
          .request(deviceLockName, { signal }, () => {
            clearTimeout(timer);
            return hold();
          })
          .catch((error: unknown) => {
            clearTimeout(timer);
            reject(error);
          });
        return undefined;
      })
      .catch(reject);
  });
}
