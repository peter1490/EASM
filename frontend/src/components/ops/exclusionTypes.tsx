import type { ExclusionObjectType } from "@/app/api";
import type { IconName } from "@/components/kit";
import { humanise } from "@/lib/format";

/** The object kinds an exclusion can cover, with the example each one needs. */
export const EXCLUSION_TYPES: Array<{
  value: ExclusionObjectType;
  label: string;
  icon: IconName;
  placeholder: string;
}> = [
  { value: "domain", label: "Domain", icon: "globe", placeholder: "e.g. cloudflare.com" },
  { value: "ip", label: "IP address", icon: "server", placeholder: "e.g. 192.168.1.1" },
  { value: "cidr", label: "CIDR range", icon: "port", placeholder: "e.g. 10.0.0.0/8" },
  { value: "asn", label: "ASN", icon: "activity", placeholder: "e.g. AS13335" },
  { value: "organization", label: "Organization", icon: "building", placeholder: "e.g. Cloudflare Inc" },
  { value: "certificate", label: "Certificate", icon: "certificate", placeholder: "Certificate fingerprint" },
];

export function exclusionType(value: string): {
  label: string;
  icon: IconName;
  placeholder: string;
} {
  return (
    EXCLUSION_TYPES.find((type) => type.value === value) ?? {
      label: humanise(value),
      icon: "ban" as IconName,
      placeholder: "Enter a value",
    }
  );
}
