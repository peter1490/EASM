"use client";

import { useState, useEffect } from "react";
import Modal from "@/components/ui/Modal";
import { Asset, getAsset, createScan, Scan, listScans } from "@/app/api";
import Button from "@/components/ui/Button";
import Badge from "@/components/ui/Badge";
import LoadingSpinner from "@/components/ui/LoadingSpinner";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";
import AssetDiscoveryGraph from "@/components/AssetDiscoveryGraph";

import Link from "next/link";

export interface AssetDetailModalProps {
  assetId: string | null;
  onClose: () => void;
}

export default function AssetDetailModal({ assetId, onClose }: AssetDetailModalProps) {
  const [asset, setAsset] = useState<Asset | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [relatedScans, setRelatedScans] = useState<Scan[]>([]);
  const [scanningNow, setScanningNow] = useState(false);
  const [scanSuccess, setScanSuccess] = useState(false);

  useEffect(() => {
    if (!assetId) return;

    const fetchAsset = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await getAsset(assetId);
        setAsset(data);

        // Fetch related scans
        const scans = await listScans();
        const filtered = scans.filter(s => s.target.toLowerCase().trim() === data.value.toLowerCase().trim());
        setRelatedScans(filtered);
      } catch (e) {
        setError((e as Error).message);
      } finally {
        setLoading(false);
      }
    };

    fetchAsset();
  }, [assetId]);

  const handleScan = async () => {
    if (!asset) return;

    setScanningNow(true);
    setScanSuccess(false);
    setError(null);

    try {
      await createScan(asset.value, `Scan from asset ${asset.value}`);
      setScanSuccess(true);

      // Refresh related scans
      const scans = await listScans();
      const filtered = scans.filter(s => s.target.toLowerCase().trim() === asset.value.toLowerCase().trim());
      setRelatedScans(filtered);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setScanningNow(false);
    }
  };

  if (!assetId) return null;

  return (
    <Modal isOpen={!!assetId} onClose={onClose} title="Asset Details" size="lg">
      {loading ? (
        <div className="py-12 flex justify-center">
          <LoadingSpinner size="lg" />
        </div>
      ) : error && !asset ? (
        <div className="p-4 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive">
          {error}
        </div>
      ) : asset ? (
        <div className="space-y-6">
          {/* Basic Info */}
          <Card>
            <CardHeader>
              <div className="flex items-start justify-between">
                <div className="space-y-1">
                  <CardTitle className="font-mono text-2xl">{asset.value}</CardTitle>
                  <CardDescription>Asset ID: {asset.id}</CardDescription>
                </div>
                <Badge variant={asset.asset_type === "domain" ? "info" : "secondary"} className="text-lg px-3 py-1">
                  {asset.asset_type}
                </Badge>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <div className="text-sm text-muted-foreground mb-1">Ownership Confidence</div>
                  <div className="flex items-center gap-3">
                    <div className="flex-1 max-w-48">
                      <div className="h-3 bg-muted rounded-full overflow-hidden">
                        <div
                          className={`h-full transition-all ${asset.ownership_confidence >= 0.7
                            ? "bg-success"
                            : asset.ownership_confidence >= 0.4
                              ? "bg-warning"
                              : "bg-destructive"
                            }`}
                          style={{ width: `${asset.ownership_confidence * 100}%` }}
                        />
                      </div>
                    </div>
                    <span className="text-lg font-semibold">
                      {(asset.ownership_confidence * 100).toFixed(0)}%
                    </span>
                  </div>
                </div>

                <div>
                  <div className="text-sm text-muted-foreground mb-1">Discovery Sources</div>
                  <div className="text-lg font-semibold">{asset.sources.length} sources</div>
                </div>

                <div>
                  <div className="text-sm text-muted-foreground mb-1">Created</div>
                  <div className="text-sm">{new Date(asset.created_at).toLocaleString()}</div>
                </div>

                <div>
                  <div className="text-sm text-muted-foreground mb-1">Last Updated</div>
                  <div className="text-sm">{new Date(asset.updated_at).toLocaleString()}</div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Sources */}
          <Card>
            <CardHeader>
              <CardTitle>Discovery Sources</CardTitle>
              <CardDescription>How this asset was discovered</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-2">
                {asset.sources.map((source, idx) => (
                  <Badge key={idx} variant="secondary" className="text-sm px-3 py-1">
                    {source}
                  </Badge>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Metadata */}
          <Card>
            <CardHeader>
              <CardTitle>Metadata</CardTitle>
              <CardDescription>Additional information about this asset</CardDescription>
            </CardHeader>
            <CardContent>
              <pre className="bg-muted rounded-lg p-4 text-xs overflow-x-auto max-h-64 overflow-y-auto">
                {JSON.stringify(asset.metadata, null, 2)}
              </pre>
            </CardContent>
          </Card>

          {/* Discovery Path */}
          <Card>
            <CardHeader>
              <CardTitle>Discovery Path</CardTitle>
              <CardDescription>Visual lineage of how this asset was discovered</CardDescription>
            </CardHeader>
            <CardContent>
              <AssetDiscoveryGraph assetId={asset.id} />
            </CardContent>
          </Card>

          {/* Scan Information */}
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Scan Information</CardTitle>
                  <CardDescription>
                    {asset.last_scanned_at
                      ? `Last scanned on ${new Date(asset.last_scanned_at).toLocaleString()}`
                      : "This asset has never been scanned"}
                  </CardDescription>
                </div>
                <Button
                  onClick={handleScan}
                  disabled={scanningNow}
                  variant="primary"
                >
                  {scanningNow ? "Scanning..." : "Run Scan Now"}
                </Button>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {scanSuccess && (
                <div className="p-3 rounded-lg bg-success/10 border border-success/20 text-success">
                  Scan initiated successfully! It will run in the background.
                </div>
              )}

              {error && !loading && (
                <div className="p-3 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive">
                  {error}
                </div>
              )}

              {asset.last_scan_status && (
                <div className="flex items-center gap-2">
                  <span className="text-sm text-muted-foreground">Last Scan Status:</span>
                  {asset.last_scan_id ? (
                    <Link href={`/scan/${asset.last_scan_id}`} className="hover:opacity-80 transition-opacity">
                      <Badge
                        variant={
                          asset.last_scan_status === "completed" ? "success" :
                            asset.last_scan_status === "failed" ? "error" :
                              "warning"
                        }
                        className="cursor-pointer"
                      >
                        {asset.last_scan_status} ↗
                      </Badge>
                    </Link>
                  ) : (
                    <Badge
                      variant={
                        asset.last_scan_status === "completed" ? "success" :
                          asset.last_scan_status === "failed" ? "error" :
                            "warning"
                      }
                    >
                      {asset.last_scan_status}
                    </Badge>
                  )}
                </div>
              )}

              {relatedScans.length > 0 && (
                <div>
                  <div className="text-sm font-medium mb-2">Related Scans ({relatedScans.length})</div>
                  <div className="space-y-2 max-h-48 overflow-y-auto">
                    {relatedScans.map(scan => (
                      <Link key={scan.id} href={`/scan/${scan.id}`}>
                        <div
                          className="flex items-center justify-between p-3 rounded-lg bg-muted hover:bg-muted/80 transition-colors cursor-pointer mb-2 last:mb-0"
                        >
                          <div className="space-y-1">
                            <div className="text-sm font-medium">{scan.target}</div>
                            <div className="text-xs text-muted-foreground">
                              {new Date(scan.created_at).toLocaleString()}
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            <Badge variant={
                              scan.status === "completed" ? "success" :
                                scan.status === "failed" ? "error" :
                                  scan.status === "running" ? "info" :
                                    "secondary"
                            }>
                              {scan.status}
                            </Badge>
                            {scan.findings_count !== undefined && (
                              <span className="text-xs text-muted-foreground">
                                {scan.findings_count} findings
                              </span>
                            )}
                          </div>
                        </div>
                      </Link>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Actions */}
          <div className="flex justify-end gap-3 pt-4 border-t border-border">
            <Button variant="outline" onClick={onClose}>
              Close
            </Button>
          </div>
        </div>
      ) : null}
    </Modal>
  );
}

