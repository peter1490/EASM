"use client";

import { useParams } from "next/navigation";
import { AssetDetail } from "@/components/asset/AssetDetail";
import { EmptyState } from "@/components/kit";

/**
 * One asset, full width.
 *
 * Deliberately thin: the body is the same `<AssetDetail>` the inventory drawer
 * renders, so a link to this page and a click on a row show exactly the same
 * thing, laid out for the room each one has.
 */
export default function AssetPage() {
  const params = useParams<{ id: string }>();
  const id = typeof params?.id === "string" ? params.id : Array.isArray(params?.id) ? params.id[0] : null;

  return (
    <div className="h-full overflow-y-auto">
      <div className="px-6 py-5">
        {id ? (
          <AssetDetail assetId={id} variant="page" />
        ) : (
          <EmptyState icon="search" title="No asset selected" description="This link is missing an asset id." />
        )}
      </div>
    </div>
  );
}
