export const deviceLockName = "ghostx-device";

export function requestDeviceLock(signal: AbortSignal): Promise<() => void> {
  const locks = typeof navigator === "undefined" ? undefined : navigator.locks;
  if (!locks) {
    return Promise.reject(new Error("unavailable"));
  }
  return new Promise((resolve, reject) => {
    locks
      .request(
        deviceLockName,
        { signal },
        () => new Promise<void>((release) => resolve(release)),
      )
      .catch(reject);
  });
}
