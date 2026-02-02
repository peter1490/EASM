export function getDiscoveryCountClasses(count: number) {
  if (count >= 500) {
    return { text: "text-destructive", badge: "bg-destructive/15 text-destructive" };
  }
  if (count >= 200) {
    return { text: "text-orange-500", badge: "bg-orange-500/15 text-orange-500" };
  }
  if (count >= 50) {
    return { text: "text-warning", badge: "bg-warning/15 text-warning" };
  }
  if (count >= 10) {
    return { text: "text-info", badge: "bg-info/15 text-info" };
  }
  return { text: "text-success", badge: "bg-success/15 text-success" };
}
