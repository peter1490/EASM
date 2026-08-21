/** Distinct items, in first-seen order.
 *
 *  Mostly for lists rendered with the value as the React key — CVE ids, tags,
 *  discovery sources. These arrive from the API as plain arrays that no one promised
 *  were distinct: findings merge CVE ids from several detected services, and assets
 *  accumulate a source per discovery run. A repeat crashes the list with a duplicate
 *  key, and would render the same chip twice even if it did not. */
export function uniq<T>(items: readonly T[]): T[] {
  return [...new Set(items)];
}
