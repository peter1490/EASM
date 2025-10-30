"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { createScan, listScans, type Scan, type ScanOptions } from "@/app/api";
import Button from "@/components/ui/Button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";
import Badge from "@/components/ui/Badge";
import Input from "@/components/ui/Input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/Table";
import EmptyState from "@/components/ui/EmptyState";
import LoadingSpinner from "@/components/ui/LoadingSpinner";
import Header from "@/components/Header";

type OptionKey = keyof Required<Pick<ScanOptions,
  | "enumerate_subdomains"
  | "resolve_dns"
  | "reverse_dns"
  | "scan_common_ports"
  | "http_probe"
  | "tls_info"
>>;

const OPTION_ENTRIES: Array<[OptionKey, string]> = [
  ["enumerate_subdomains", "Enumerate subdomains"],
  ["resolve_dns", "Resolve DNS"],
  ["reverse_dns", "Reverse DNS"],
  ["scan_common_ports", "Scan ports"],
  ["http_probe", "HTTP probe"],
  ["tls_info", "TLS info"],
];

export default function Dashboard() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [target, setTarget] = useState("");
  const [note, setNote] = useState("");
  const [opts, setOpts] = useState<ScanOptions>({});
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);

  async function refresh() {
    try {
      const data = await listScans();
      setScans(data);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 2000);
    return () => clearInterval(id);
  }, []);

  async function onCreate() {
    if (!target.trim()) return;
    setError(null);
    setCreating(true);
    try {
      await createScan(target.trim(), note.trim() || undefined, opts);
      setTarget("");
      setNote("");
      await refresh();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setCreating(false);
    }
  }

  const stats = {
    total: scans.length,
    completed: scans.filter(s => s.status === "completed").length,
    running: scans.filter(s => s.status !== "completed" && s.status !== "failed").length,
    findings: scans.reduce((acc, s) => acc + (s.findings_count ?? s.findings?.length ?? 0), 0),
  };

  const recentScans = scans.slice(0, 5);

  return (
    <div className="space-y-8 animate-fade-in">
      <Header 
        title="Dashboard" 
        description="Monitor and manage your attack surface scans"
      />

      {/* Stats Cards */}
      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="pb-3">
            <CardDescription>Total Scans</CardDescription>
            <CardTitle className="text-3xl">{stats.total}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-xs text-muted-foreground">
              All scan operations
            </div>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="pb-3">
            <CardDescription>Completed</CardDescription>
            <CardTitle className="text-3xl text-success">{stats.completed}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-xs text-muted-foreground">
              Successfully finished
            </div>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="pb-3">
            <CardDescription>Active Scans</CardDescription>
            <CardTitle className="text-3xl text-warning">{stats.running}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-xs text-muted-foreground">
              Currently scanning
            </div>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="pb-3">
            <CardDescription>Total Findings</CardDescription>
            <CardTitle className="text-3xl text-info">{stats.findings}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-xs text-muted-foreground">
              Discovered vulnerabilities
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Create New Scan */}
      <Card>
        <CardHeader>
          <CardTitle>Create New Scan</CardTitle>
          <CardDescription>
            Start a new security scan for a domain, IP address, or CIDR range
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <Input
              label="Target"
              placeholder="example.com, 1.2.3.4, or 10.0.0.0/24"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && onCreate()}
            />
            <Input
              label="Note (optional)"
              placeholder="Add a description for this scan"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && onCreate()}
            />
          </div>

          <div>
            <button
              onClick={() => setShowAdvanced(!showAdvanced)}
              className="text-sm text-primary hover:underline mb-3"
            >
              {showAdvanced ? "Hide" : "Show"} Advanced Options
            </button>
            
            {showAdvanced && (
              <div className="grid grid-cols-2 md:grid-cols-3 gap-3 p-4 bg-muted rounded-lg">
                {OPTION_ENTRIES.map(([key, label]) => {
                  const current = (opts as Record<string, unknown>)[key];
                  const checked = typeof current === "boolean" ? current : true;
                  return (
                    <label key={key} className="flex items-center gap-2 text-sm cursor-pointer">
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={(e) => setOpts((o) => ({ ...o, [key]: e.target.checked }))}
                        className="h-4 w-4 rounded border-border text-primary focus:ring-2 focus:ring-ring"
                      />
                      <span>{label}</span>
                    </label>
                  );
                })}
              </div>
            )}
          </div>

          {error && (
            <div className="p-3 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive text-sm">
              {error}
            </div>
          )}

          <div className="flex gap-3">
            <Button
              onClick={onCreate}
              disabled={!target.trim()}
              loading={creating}
              size="lg"
            >
              Start Scan
            </Button>
            <Button
              variant="outline"
              onClick={() => {
                setTarget("");
                setNote("");
                setOpts({});
                setError(null);
              }}
              disabled={creating}
            >
              Clear
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Recent Scans */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Recent Scans</CardTitle>
              <CardDescription>
                Latest scan operations and their status
              </CardDescription>
            </div>
            <Link href="/assets">
              <Button variant="outline" size="sm">View All Assets →</Button>
            </Link>
          </div>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="py-12">
              <LoadingSpinner size="lg" />
            </div>
          ) : scans.length === 0 ? (
            <EmptyState
              icon="🔍"
              title="No scans yet"
              description="Create your first scan above to start discovering your attack surface"
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Target</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Findings</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {recentScans.map((scan) => (
                  <TableRow key={scan.id}>
                    <TableCell className="font-medium font-mono">
                      {scan.target}
                    </TableCell>
                    <TableCell>
                      <Badge 
                        variant={
                          scan.status === "completed" ? "success" : 
                          scan.status === "failed" ? "error" : 
                          "warning"
                        }
                      >
                        {scan.status}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <span className="font-medium">
                          {scan.findings_count ?? scan.findings?.length ?? 0}
                        </span>
                        <span className="text-xs text-muted-foreground">findings</span>
                      </div>
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {new Date(scan.created_at).toLocaleString()}
                    </TableCell>
                    <TableCell className="text-right">
                      <Link href={`/scan/${scan.id}`}>
                        <Button variant="ghost" size="sm">
                          View Details →
                        </Button>
                      </Link>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
