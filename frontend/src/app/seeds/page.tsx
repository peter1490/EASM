"use client";

import { useEffect, useState } from "react";
import { createSeed, deleteSeed, listSeeds, runDiscovery, getDiscoveryStatus, type Seed, type SeedType, type DiscoveryStatus } from "@/app/api";
import Button from "@/components/ui/Button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";
import Badge from "@/components/ui/Badge";
import Input from "@/components/ui/Input";
import Select from "@/components/ui/Select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/Table";
import EmptyState from "@/components/ui/EmptyState";
import LoadingSpinner from "@/components/ui/LoadingSpinner";
import Header from "@/components/Header";

const SEED_TYPES: Array<{ value: SeedType; label: string; icon: string; description: string }> = [
  { value: "root_domain", label: "Root Domain", icon: "🌐", description: "e.g., example.com" },
  { value: "acquisition_domain", label: "Acquisition Domain", icon: "🏢", description: "Domain from acquisition" },
  { value: "cidr", label: "CIDR Range", icon: "📡", description: "e.g., 10.0.0.0/24" },
  { value: "asn", label: "ASN", icon: "🔢", description: "e.g., AS12345" },
  { value: "keyword", label: "Keyword", icon: "🔑", description: "Search keyword" },
  { value: "organization", label: "Organization", icon: "🏛️", description: "Company name" },
];

export default function SeedsPage() {
  const [seeds, setSeeds] = useState<Seed[]>([]);
  const [loading, setLoading] = useState(true);
  const [seedType, setSeedType] = useState<SeedType>("root_domain");
  const [value, setValue] = useState("");
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [discovering, setDiscovering] = useState(false);
  const [discoveryStatus, setDiscoveryStatus] = useState<DiscoveryStatus | null>(null);
  const [confidence, setConfidence] = useState(0.7);

  async function refresh() {
    try {
      const data = await listSeeds();
      setSeeds(data);
      setLoading(false);
    } catch (e) {
      setError((e as Error).message);
      setLoading(false);
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  useEffect(() => {
    let timer: NodeJS.Timeout | null = null;
    async function poll() {
      try {
        const s = await getDiscoveryStatus();
        setDiscoveryStatus(s);
      } catch {
        // ignore
      }
      timer = setTimeout(poll, 2000);
    }
    poll();
    return () => { if (timer) clearTimeout(timer); };
  }, []);

  async function onAdd() {
    if (!value.trim()) return;
    setError(null);
    setAdding(true);
    try {
      await createSeed({ seed_type: seedType, value: value.trim(), note: note.trim() || undefined });
      setValue("");
      setNote("");
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setAdding(false);
    }
  }

  async function onDelete(id: string) {
    try {
      await deleteSeed(id);
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function onRunDiscovery() {
    setError(null);
    if (discoveryStatus?.running) {
      setError("Discovery already running");
      return;
    }
    setDiscovering(true);
    try {
      await runDiscovery({ confidence_threshold: confidence, include_scan: true });
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setDiscovering(false);
    }
  }

  const stats = {
    total: seeds.length,
    byType: SEED_TYPES.map(type => ({
      ...type,
      count: seeds.filter(s => s.seed_type === type.value).length,
    })),
  };

  const selectedType = SEED_TYPES.find(t => t.value === seedType);

  return (
    <div className="space-y-8 animate-fade-in">
      <Header 
        title="Seed Management" 
        description="Configure discovery seeds to find your attack surface"
      />

      {/* Discovery Status */}
      {discoveryStatus?.running && (
        <Card className="border-warning bg-warning/5">
          <CardContent className="py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <LoadingSpinner size="sm" />
                <div>
                  <div className="font-medium text-warning">Discovery in Progress</div>
                  <div className="text-sm text-muted-foreground">
                    Enumerating subdomains and discovering new assets
                  </div>
                </div>
              </div>
              <div className="flex gap-4 text-sm">
                <div className="text-right">
                  <div className="text-muted-foreground">Seeds Processed</div>
                  <div className="font-semibold">{discoveryStatus.seeds_processed}</div>
                </div>
                <div className="text-right">
                  <div className="text-muted-foreground">Assets Discovered</div>
                  <div className="font-semibold">{discoveryStatus.assets_discovered}</div>
                </div>
                {discoveryStatus.error_count > 0 && (
                  <div className="text-right">
                    <div className="text-muted-foreground">Errors</div>
                    <div className="font-semibold text-destructive">{discoveryStatus.error_count}</div>
                  </div>
                )}
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Stats */}
      <div className="grid gap-6 md:grid-cols-3 lg:grid-cols-6">
        <Card>
          <CardHeader className="pb-3">
            <CardDescription>Total Seeds</CardDescription>
            <CardTitle className="text-2xl">{stats.total}</CardTitle>
          </CardHeader>
        </Card>
        {stats.byType.filter(t => t.count > 0).slice(0, 5).map((type) => (
          <Card key={type.value}>
            <CardHeader className="pb-3">
              <CardDescription className="flex items-center gap-1">
                <span>{type.icon}</span>
                <span>{type.label}</span>
              </CardDescription>
              <CardTitle className="text-2xl">{type.count}</CardTitle>
            </CardHeader>
          </Card>
        ))}
      </div>

      {/* Add New Seed */}
      <Card>
        <CardHeader>
          <CardTitle>Add New Seed</CardTitle>
          <CardDescription>
            Seeds are starting points for asset discovery
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 md:grid-cols-3">
            <Select
              label="Seed Type"
              value={seedType}
              onChange={(e) => setSeedType(e.target.value as SeedType)}
            >
              {SEED_TYPES.map((t) => (
                <option key={t.value} value={t.value}>
                  {t.icon} {t.label}
                </option>
              ))}
            </Select>
            <Input
              label="Value"
              placeholder={selectedType?.description || "Enter value"}
              value={value}
              onChange={(e) => setValue(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && onAdd()}
            />
            <Input
              label="Note (optional)"
              placeholder="Add a description"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && onAdd()}
            />
          </div>

          {error && (
            <div className="p-3 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive text-sm">
              {error}
            </div>
          )}

          <div className="flex gap-3">
            <Button
              onClick={onAdd}
              disabled={!value.trim()}
              loading={adding}
            >
              Add Seed
            </Button>
            <Button
              variant="outline"
              onClick={() => {
                setValue("");
                setNote("");
                setError(null);
              }}
              disabled={adding}
            >
              Clear
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Run Discovery */}
      <Card>
        <CardHeader>
          <CardTitle>Run Discovery</CardTitle>
          <CardDescription>
            Start the asset discovery process using your configured seeds
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-end gap-4">
            <div className="flex-1">
              <label className="block text-sm font-medium text-foreground mb-1.5">
                Confidence Threshold: {confidence.toFixed(2)}
              </label>
              <input
                type="range"
                min={0}
                max={1}
                step={0.05}
                value={confidence}
                onChange={(e) => setConfidence(parseFloat(e.target.value))}
                className="w-full h-10 accent-primary"
                disabled={discoveryStatus?.running}
              />
              <div className="flex justify-between text-xs text-muted-foreground mt-1">
                <span>Low (0.0)</span>
                <span>Medium (0.5)</span>
                <span>High (1.0)</span>
              </div>
            </div>
            <Button
              onClick={onRunDiscovery}
              disabled={discoveryStatus?.running || seeds.length === 0}
              loading={discovering}
              size="lg"
            >
              {discoveryStatus?.running ? "Discovery Running..." : "Start Discovery"}
            </Button>
          </div>
          <div className="p-3 rounded-lg bg-info/10 border border-info/20 text-sm">
            <div className="font-medium text-info mb-1">ℹ️ About Discovery</div>
            <div className="text-muted-foreground">
              Discovery will enumerate subdomains, resolve DNS, and schedule scans for assets 
              that meet the confidence threshold. Assets with higher confidence scores are more 
              likely to belong to your organization.
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Seeds Table */}
      <Card>
        <CardHeader>
          <CardTitle>Configured Seeds ({seeds.length})</CardTitle>
          <CardDescription>
            All discovery starting points
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="py-12">
              <LoadingSpinner size="lg" />
            </div>
          ) : seeds.length === 0 ? (
            <EmptyState
              icon="🌱"
              title="No seeds configured"
              description="Add your first seed above to start discovering your attack surface"
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Type</TableHead>
                  <TableHead>Value</TableHead>
                  <TableHead>Note</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {seeds.map((seed) => {
                  const typeInfo = SEED_TYPES.find(t => t.value === seed.seed_type);
                  return (
                    <TableRow key={seed.id}>
                      <TableCell>
                        <Badge variant="info">
                          {typeInfo?.icon} {typeInfo?.label || seed.seed_type}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-medium font-mono">
                        {seed.value}
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {seed.note || "—"}
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {new Date(seed.created_at).toLocaleString()}
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => onDelete(seed.id)}
                          className="text-destructive hover:text-destructive"
                        >
                          Delete
                        </Button>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
