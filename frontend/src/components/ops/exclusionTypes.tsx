import type { ExclusionObjectType } from "@/app/api";
import type { IconName } from "@/components/kit";
import { humanise } from "@/lib/format";

/** The object kinds an exclusion can cover, with the example each one needs. */
export const EXCLUSION_TYPES: Array<{
  value: ExclusionObjectType;
  label: string;
  icon: IconName;
  placeholder: string;
  /**
   * Whether a `*` in the value means "anything here".
   *
   * Only the free-text kinds. A range of addresses already has a notation of
   * its own — that is what a CIDR entry is — and `AS*` is not something anyone
   * means by an autonomous system number.
   */
  wildcards?: true;
}> = [
  {
    value: "domain",
    label: "Domain",
    icon: "globe",
    placeholder: "e.g. cloudflare.com or *.cdn.example.com",
    wildcards: true,
  },
  { value: "ip", label: "IP address", icon: "server", placeholder: "e.g. 192.168.1.1" },
  { value: "cidr", label: "CIDR range", icon: "port", placeholder: "e.g. 10.0.0.0/8" },
  { value: "asn", label: "ASN", icon: "activity", placeholder: "e.g. AS13335" },
  {
    value: "organization",
    label: "Organization",
    icon: "building",
    placeholder: "e.g. Cloudflare Inc or *hosting*",
    wildcards: true,
  },
  {
    value: "certificate",
    label: "Certificate",
    icon: "certificate",
    placeholder: "Fingerprint, or CN=*.example.com",
    wildcards: true,
  },
];

/** The character that stands for "anything" in an exclusion value. */
export const WILDCARD = "*";

/** Whether a value is a pattern rather than a literal. */
export function isPattern(value: string): boolean {
  return value.includes(WILDCARD);
}

export function exclusionType(value: string): {
  label: string;
  icon: IconName;
  placeholder: string;
  wildcards?: true;
} {
  return (
    EXCLUSION_TYPES.find((type) => type.value === value) ?? {
      label: humanise(value),
      icon: "ban" as IconName,
      placeholder: "Enter a value",
    }
  );
}
