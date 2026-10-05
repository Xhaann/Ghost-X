export class Listeners<T> {
  readonly #listeners = new Set<(value: T) => void>();

  add(listener: (value: T) => void): () => void {
    this.#listeners.add(listener);
    return () => {
      this.#listeners.delete(listener);
    };
  }

  emit(value: T): void {
    for (const listener of this.#listeners) {
      listener(value);
    }
  }
}
