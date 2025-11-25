"use client";

import { useEffect, useState } from "react";
import { 
  getHealth, 
  getMetrics, 
  listUsers, 
  updateUserRole, 
  type SystemMetrics, 
  type UserWithRoles 
} from "@/app/api";
import { useAuth } from "@/context/AuthContext";
import Header from "@/components/Header";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/Table";
import Badge from "@/components/ui/Badge";
import Button from "@/components/ui/Button";
import Select from "@/components/ui/Select";
import LoadingSpinner from "@/components/ui/LoadingSpinner";
import EmptyState from "@/components/ui/EmptyState";
import Modal from "@/components/ui/Modal";

type TabType = "status" | "users";

const ROLE_COLORS: Record<string, "error" | "warning" | "info" | "secondary" | "success"> = {
  admin: "error",
  operator: "warning",
  analyst: "info",
  viewer: "secondary",
};

const ROLE_DESCRIPTIONS: Record<string, string> = {
  admin: "Full access - can manage users and all settings",
  operator: "Can run scans, discovery, and modify assets",
  analyst: "Can view assets, findings, and update importance",
  viewer: "Read-only access to all data",
};

const ALL_ROLES = ["admin", "operator", "analyst", "viewer"];

export default function SettingsPage() {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState<TabType>("status");
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);
  const [health, setHealth] = useState<{ status: string; version: string } | null>(null);
  const [users, setUsers] = useState<UserWithRoles[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [updating, setUpdating] = useState<string | null>(null);
  
  // Edit user modal
  const [selectedUser, setSelectedUser] = useState<UserWithRoles | null>(null);
  const [selectedRole, setSelectedRole] = useState("");

  const isAdmin = user?.roles?.includes("admin");

  async function loadData() {
    try {
      setLoading(true);
      const [m, h] = await Promise.all([getMetrics(), getHealth()]);
      setMetrics(m);
      setHealth(h);
      
      if (isAdmin) {
        const usersData = await listUsers();
        setUsers(usersData);
      }
      
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
    const iv = setInterval(loadData, 10000);
    return () => clearInterval(iv);
  }, [isAdmin]);

  async function handleAddRole(userId: string, role: string) {
    if (!role) return;
    setUpdating(userId);
    try {
      await updateUserRole(userId, role, "add");
      loadData();
      setSelectedRole("");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setUpdating(null);
    }
  }

  async function handleRemoveRole(userId: string, role: string) {
    setUpdating(userId);
    try {
      await updateUserRole(userId, role, "remove");
      loadData();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setUpdating(null);
    }
  }

  function formatBytes(bytes: number) {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  }

  function formatUptime(seconds: number) {
    const days = Math.floor(seconds / (3600 * 24));
    const hours = Math.floor((seconds % (3600 * 24)) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    return `${days}d ${hours}h ${minutes}m`;
  }

  const tabs = [
    { id: "status" as TabType, label: "System Status", icon: "⚙️" },
    ...(isAdmin ? [{ id: "users" as TabType, label: "User Management", icon: "👥", badge: users.length }] : []),
  ];

  return (
    <div className="space-y-8 animate-fade-in">
      <Header 
        title="Settings" 
        description="System status and administration"
      />

      {/* Tab Navigation */}
      <div className="tab-list">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`tab-item flex items-center gap-2 ${activeTab === tab.id ? "active" : ""}`}
          >
            <span>{tab.icon}</span>
            <span>{tab.label}</span>
            {tab.badge !== undefined && tab.badge > 0 && (
              <span className="ml-1 px-1.5 py-0.5 bg-primary/20 text-primary text-xs rounded-full font-medium">
                {tab.badge}
              </span>
            )}
          </button>
        ))}
      </div>

      {error && (
        <Card className="border-destructive/50 bg-destructive/5">
          <CardContent className="py-4">
            <div className="text-destructive flex items-center gap-2">
              <span>⚠️</span>
              <span>{error}</span>
            </div>
          </CardContent>
        </Card>
      )}

      {/* System Status Tab */}
      {activeTab === "status" && (
        <>
          {loading && !metrics ? (
            <div className="flex items-center justify-center py-12">
              <LoadingSpinner size="lg" />
            </div>
          ) : metrics && health ? (
            <div className="space-y-6 stagger-children">
              {/* System Overview */}
              <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
                <Card className="group hover:shadow-lg transition-all">
                  <CardHeader className="pb-3">
                    <CardDescription>System Status</CardDescription>
                    <CardTitle className="flex items-center gap-3">
                      <div className={`h-4 w-4 rounded-full ${health.status === "healthy" || health.status === "ok" ? "bg-success animate-pulse-glow" : "bg-destructive"}`} />
                      <span className="font-mono">{health.status.toUpperCase()}</span>
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-xs text-muted-foreground">
                      Version: <span className="font-mono">{health.version}</span>
                    </div>
                  </CardContent>
                </Card>

                <Card className="group hover:shadow-lg transition-all">
                  <CardHeader className="pb-3">
                    <CardDescription>Uptime</CardDescription>
                    <CardTitle className="font-mono">{formatUptime(metrics.uptime_seconds)}</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-xs text-muted-foreground">Since last restart</div>
                  </CardContent>
                </Card>

                <Card className="group hover:shadow-lg transition-all">
                  <CardHeader className="pb-3">
                    <CardDescription>Memory Usage</CardDescription>
                    <CardTitle className="font-mono">{formatBytes(metrics.memory_usage.used_bytes)}</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-xs text-muted-foreground mb-2">
                      of {formatBytes(metrics.memory_usage.total_bytes)} total
                    </div>
                    <div className="h-2 w-full bg-muted rounded-full overflow-hidden">
                      <div 
                        className="h-full bg-primary transition-all duration-500" 
                        style={{ width: `${(metrics.memory_usage.used_bytes / metrics.memory_usage.total_bytes) * 100}%` }}
                      />
                    </div>
                  </CardContent>
                </Card>

                <Card className="group hover:shadow-lg transition-all">
                  <CardHeader className="pb-3">
                    <CardDescription>CPU Usage</CardDescription>
                    <CardTitle className="font-mono">{metrics.cpu_usage_percent.toFixed(1)}%</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-xs text-muted-foreground mb-2">Current load</div>
                    <div className="h-2 w-full bg-muted rounded-full overflow-hidden">
                      <div 
                        className={`h-full transition-all duration-500 ${metrics.cpu_usage_percent > 80 ? "bg-destructive" : metrics.cpu_usage_percent > 50 ? "bg-warning" : "bg-success"}`}
                        style={{ width: `${Math.min(metrics.cpu_usage_percent, 100)}%` }}
                      />
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* Application Stats */}
              <div className="grid gap-6 md:grid-cols-2">
                <Card>
                  <CardHeader>
                    <CardTitle>Application Statistics</CardTitle>
                    <CardDescription>Core metrics for the EASM platform</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    {[
                      { icon: "🎯", label: "Total Assets", value: metrics.total_assets, color: "text-foreground" },
                      { icon: "🔍", label: "Total Findings", value: metrics.total_findings, color: "text-info" },
                      { icon: "⚡", label: "Active Scans", value: metrics.active_scans, color: "text-warning" },
                      { icon: "🚀", label: "Requests/sec", value: metrics.requests_per_second.toFixed(2), color: "text-success" },
                    ].map((stat, idx) => (
                      <div key={idx} className="flex items-center justify-between p-4 border border-border rounded-lg hover:bg-muted/30 transition-colors">
                        <div className="flex items-center gap-3">
                          <span className="text-2xl">{stat.icon}</span>
                          <div className="font-medium">{stat.label}</div>
                        </div>
                        <span className={`text-2xl font-bold font-mono ${stat.color}`}>{stat.value}</span>
                      </div>
                    ))}
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle>Feature Status</CardTitle>
                    <CardDescription>Operational status of system components</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      {[
                        { name: "Scanner Engine", status: "operational" },
                        { name: "Drift Detection", status: "operational" },
                        { name: "Search Index", status: "operational" },
                        { name: "Risk Scoring", status: "operational" },
                        { name: "Discovery Engine", status: "operational" },
                      ].map((component) => (
                        <div key={component.name} className="flex items-center justify-between p-3 border border-border rounded-lg">
                          <div className="flex items-center gap-3">
                            <div className="h-2.5 w-2.5 rounded-full bg-success animate-pulse" />
                            <span>{component.name}</span>
                          </div>
                          <Badge variant="success" className="font-mono text-xs">
                            {component.status}
                          </Badge>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              </div>
            </div>
          ) : null}
        </>
      )}

      {/* User Management Tab */}
      {activeTab === "users" && isAdmin && (
        <div className="space-y-6 stagger-children">
          {/* User Stats */}
          <div className="grid gap-4 md:grid-cols-4">
            <Card>
              <CardHeader className="pb-2">
                <CardDescription>Total Users</CardDescription>
                <CardTitle className="text-3xl font-mono">{users.filter(u => u.user).length}</CardTitle>
              </CardHeader>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardDescription>Admins</CardDescription>
                <CardTitle className="text-3xl font-mono text-destructive">
                  {users.filter(u => u.roles?.includes("admin")).length}
                </CardTitle>
              </CardHeader>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardDescription>Operators</CardDescription>
                <CardTitle className="text-3xl font-mono text-warning">
                  {users.filter(u => u.roles?.includes("operator")).length}
                </CardTitle>
              </CardHeader>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardDescription>Active</CardDescription>
                <CardTitle className="text-3xl font-mono text-success">
                  {users.filter(u => u.user?.is_active).length}
                </CardTitle>
              </CardHeader>
            </Card>
          </div>

          {/* Role Legend */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Role Definitions</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid gap-3 md:grid-cols-2">
                {ALL_ROLES.map((role) => (
                  <div key={role} className="flex items-start gap-3 p-3 border border-border rounded-lg">
                    <Badge variant={ROLE_COLORS[role] || "secondary"} className="mt-0.5">
                      {role}
                    </Badge>
                    <div className="text-sm text-muted-foreground">
                      {ROLE_DESCRIPTIONS[role]}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Users Table */}
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Users</CardTitle>
                  <CardDescription>Manage user accounts and roles</CardDescription>
                </div>
                <Button variant="outline" onClick={loadData}>Refresh</Button>
              </div>
            </CardHeader>
            <CardContent>
              {loading ? (
                <div className="flex justify-center py-12">
                  <LoadingSpinner size="lg" />
                </div>
              ) : users.length === 0 ? (
                <EmptyState
                  icon="👤"
                  title="No users found"
                  description="Users will appear here after they sign in"
                />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>User</TableHead>
                      <TableHead>Email</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Roles</TableHead>
                      <TableHead>Created</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {users.filter(u => u.user).map((u) => (
                      <TableRow key={u.user.id}>
                        <TableCell>
                          <div className="flex items-center gap-3">
                            <div className="h-9 w-9 rounded-full bg-gradient-to-br from-primary/20 to-info/20 flex items-center justify-center text-primary font-medium">
                              {u.user.display_name?.[0] || u.user.email?.[0]?.toUpperCase() || "?"}
                            </div>
                            <div>
                              <div className="font-medium">{u.user.display_name || "—"}</div>
                              <div className="text-xs text-muted-foreground font-mono">
                                {u.user.id?.slice(0, 8)}...
                              </div>
                            </div>
                          </div>
                        </TableCell>
                        <TableCell className="font-mono text-sm">{u.user.email || "—"}</TableCell>
                        <TableCell>
                          <Badge variant={u.user.is_active ? "success" : "error"}>
                            {u.user.is_active ? "Active" : "Inactive"}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-1">
                            {(u.roles || []).map((role) => (
                              <Badge 
                                key={role} 
                                variant={ROLE_COLORS[role] || "secondary"}
                                className="cursor-pointer hover:opacity-80 transition-opacity"
                                onClick={() => {
                                  if (updating !== u.user.id) {
                                    handleRemoveRole(u.user.id, role);
                                  }
                                }}
                                title="Click to remove"
                              >
                                {role} ×
                              </Badge>
                            ))}
                            {(!u.roles || u.roles.length === 0) && (
                              <span className="text-muted-foreground text-sm">No roles</span>
                            )}
                          </div>
                        </TableCell>
                        <TableCell className="text-muted-foreground text-sm">
                          {u.user.created_at ? new Date(u.user.created_at).toLocaleDateString() : "—"}
                        </TableCell>
                        <TableCell className="text-right">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => setSelectedUser(u)}
                            disabled={updating === u.user.id}
                          >
                            {updating === u.user.id ? "..." : "Manage"}
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {/* User Edit Modal */}
      <Modal
        isOpen={!!selectedUser}
        onClose={() => { setSelectedUser(null); setSelectedRole(""); }}
        title="Manage User Roles"
      >
        {selectedUser && (
          <div className="space-y-6">
            <div className="flex items-center gap-4">
              <div className="h-14 w-14 rounded-full bg-gradient-to-br from-primary/20 to-info/20 flex items-center justify-center text-primary text-xl font-medium">
                {selectedUser.user.display_name?.[0] || selectedUser.user.email[0].toUpperCase()}
              </div>
              <div>
                <div className="font-medium text-lg">
                  {selectedUser.user.display_name || selectedUser.user.email}
                </div>
                <div className="text-sm text-muted-foreground">{selectedUser.user.email}</div>
              </div>
            </div>

            <div>
              <h4 className="font-medium mb-3">Current Roles</h4>
              <div className="flex flex-wrap gap-2">
                {selectedUser.roles.length > 0 ? (
                  selectedUser.roles.map((role) => (
                    <div key={role} className="flex items-center gap-2 p-2 bg-muted rounded-lg">
                      <Badge variant={ROLE_COLORS[role] || "secondary"}>{role}</Badge>
                      <Button
                        size="sm"
                        variant="ghost"
                        className="h-6 w-6 p-0 text-destructive hover:text-destructive"
                        onClick={() => handleRemoveRole(selectedUser.user.id, role)}
                        disabled={updating === selectedUser.user.id}
                      >
                        ×
                      </Button>
                    </div>
                  ))
                ) : (
                  <span className="text-muted-foreground">No roles assigned</span>
                )}
              </div>
            </div>

            <div>
              <h4 className="font-medium mb-3">Add Role</h4>
              <div className="flex gap-3">
                <Select
                  value={selectedRole}
                  onChange={(e) => setSelectedRole(e.target.value)}
                  className="flex-1"
                >
                  <option value="">Select a role...</option>
                  {ALL_ROLES.filter(r => !selectedUser.roles.includes(r)).map((role) => (
                    <option key={role} value={role}>{role}</option>
                  ))}
                </Select>
                <Button
                  onClick={() => handleAddRole(selectedUser.user.id, selectedRole)}
                  disabled={!selectedRole || updating === selectedUser.user.id}
                >
                  Add Role
                </Button>
              </div>
            </div>

            <div className="pt-4 border-t">
              <Button
                variant="outline"
                onClick={() => { setSelectedUser(null); setSelectedRole(""); }}
              >
                Close
              </Button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
