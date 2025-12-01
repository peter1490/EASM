"use client";

import { useEffect, useState, useCallback } from "react";
import {
  listTags,
  createTag,
  updateTag,
  deleteTag,
  runAutoTagForTag,
  runAutoTagAll,
  type TagWithCount,
  type TagCreate,
  type TagUpdate,
  type AutoTagResult,
} from "@/app/api";
import Button from "@/components/ui/Button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";
import Badge from "@/components/ui/Badge";
import Input from "@/components/ui/Input";
import Select from "@/components/ui/Select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/Table";
import EmptyState from "@/components/ui/EmptyState";
import LoadingSpinner from "@/components/ui/LoadingSpinner";
import Modal from "@/components/ui/Modal";
import Header from "@/components/Header";

const DEFAULT_COLORS = [
  "#6366f1", // indigo
  "#8b5cf6", // violet
  "#ec4899", // pink
  "#ef4444", // red
  "#f97316", // orange
  "#eab308", // yellow
  "#22c55e", // green
  "#14b8a6", // teal
  "#06b6d4", // cyan
  "#3b82f6", // blue
];

export default function TagsPage() {
  const [tags, setTags] = useState<TagWithCount[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [totalCount, setTotalCount] = useState(0);

  // Modal states
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [editingTag, setEditingTag] = useState<TagWithCount | null>(null);
  const [deletingTag, setDeletingTag] = useState<TagWithCount | null>(null);

  // Form state
  const [formData, setFormData] = useState<TagCreate>({
    name: "",
    description: "",
    importance: 3,
    rule_type: undefined,
    rule_value: "",
    color: DEFAULT_COLORS[0],
  });
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // Auto-tag states
  const [runningAutoTag, setRunningAutoTag] = useState<string | null>(null);
  const [autoTagResult, setAutoTagResult] = useState<AutoTagResult | null>(null);

  const loadTags = useCallback(async () => {
    try {
      setLoading(true);
      const response = await listTags(100, 0);
      setTags(response.tags);
      setTotalCount(response.total_count);
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadTags();
  }, [loadTags]);

  const handleCreate = async () => {
    if (!formData.name.trim()) {
      setFormError("Tag name is required");
      return;
    }

    setSubmitting(true);
    setFormError(null);

    try {
      const payload: TagCreate = {
        name: formData.name.trim(),
        description: formData.description?.trim() || undefined,
        importance: formData.importance,
        color: formData.color,
      };

      // Only include rule if both type and value are set
      if (formData.rule_type && formData.rule_value?.trim()) {
        payload.rule_type = formData.rule_type;
        payload.rule_value = formData.rule_value.trim();
      }

      await createTag(payload);
      setShowCreateModal(false);
      resetForm();
      loadTags();
    } catch (e) {
      setFormError((e as Error).message);
    } finally {
      setSubmitting(false);
    }
  };

  const handleUpdate = async () => {
    if (!editingTag) return;
    if (!formData.name.trim()) {
      setFormError("Tag name is required");
      return;
    }

    setSubmitting(true);
    setFormError(null);

    try {
      const payload: TagUpdate = {
        name: formData.name.trim(),
        description: formData.description?.trim() || undefined,
        importance: formData.importance,
        color: formData.color,
      };

      // Handle rule updates
      if (!formData.rule_type || !formData.rule_value?.trim()) {
        // Clear rule if no type or value
        payload.clear_rule = true;
      } else {
        payload.rule_type = formData.rule_type;
        payload.rule_value = formData.rule_value.trim();
      }

      await updateTag(editingTag.id, payload);
      setEditingTag(null);
      resetForm();
      loadTags();
    } catch (e) {
      setFormError((e as Error).message);
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async () => {
    if (!deletingTag) return;

    setSubmitting(true);
    try {
      await deleteTag(deletingTag.id);
      setDeletingTag(null);
      loadTags();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSubmitting(false);
    }
  };

  const handleRunAutoTag = async (tagId: string) => {
    setRunningAutoTag(tagId);
    setAutoTagResult(null);

    try {
      const result = await runAutoTagForTag(tagId);
      setAutoTagResult(result);
      loadTags(); // Refresh to update counts
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setRunningAutoTag(null);
    }
  };

  const handleRunAutoTagAll = async () => {
    setRunningAutoTag("all");
    setAutoTagResult(null);

    try {
      const result = await runAutoTagAll();
      setAutoTagResult(result);
      loadTags(); // Refresh to update counts
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setRunningAutoTag(null);
    }
  };

  const resetForm = () => {
    setFormData({
      name: "",
      description: "",
      importance: 3,
      rule_type: undefined,
      rule_value: "",
      color: DEFAULT_COLORS[Math.floor(Math.random() * DEFAULT_COLORS.length)],
    });
    setFormError(null);
  };

  const openEditModal = (tag: TagWithCount) => {
    setFormData({
      name: tag.name,
      description: tag.description || "",
      importance: tag.importance,
      rule_type: tag.rule_type || undefined,
      rule_value: tag.rule_value || "",
      color: tag.color || DEFAULT_COLORS[0],
    });
    setEditingTag(tag);
  };

  const ImportanceShields = ({ count, max = 5 }: { count: number; max?: number }) => (
    <div className="flex items-center gap-0.5">
      {Array.from({ length: max }).map((_, i) => (
        <svg
          key={i}
          className={`w-4 h-4 ${i < count ? "text-primary" : "text-muted-foreground/30"}`}
          viewBox="0 0 24 24"
          fill="currentColor"
        >
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        </svg>
      ))}
    </div>
  );

  return (
    <div className="space-y-8 animate-fade-in">
      <Header
        title="Tags"
        description="Manage asset tags with optional auto-tagging rules"
      />

      {/* Auto-tag Result Banner */}
      {autoTagResult && (
        <Card className={autoTagResult.errors.length > 0 ? "border-warning bg-warning/5" : "border-success bg-success/5"}>
          <CardContent className="py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <span className="text-2xl">{autoTagResult.errors.length > 0 ? "⚠️" : "✅"}</span>
                <div>
                  <div className="font-medium">
                    Auto-tagging {autoTagResult.errors.length > 0 ? "completed with warnings" : "completed"}
                  </div>
                  <div className="text-sm text-muted-foreground">
                    Tagged {autoTagResult.assets_tagged} assets with {autoTagResult.tags_applied} tag applications
                  </div>
                </div>
              </div>
              <Button variant="outline" size="sm" onClick={() => setAutoTagResult(null)}>
                Dismiss
              </Button>
            </div>
            {autoTagResult.errors.length > 0 && (
              <div className="mt-3 p-2 bg-warning/10 rounded text-sm">
                <div className="font-medium text-warning mb-1">Errors:</div>
                <ul className="list-disc list-inside text-muted-foreground">
                  {autoTagResult.errors.slice(0, 5).map((err, i) => (
                    <li key={i}>{err}</li>
                  ))}
                  {autoTagResult.errors.length > 5 && (
                    <li>...and {autoTagResult.errors.length - 5} more</li>
                  )}
                </ul>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Stats Cards */}
      <div className="grid gap-6 md:grid-cols-3">
        <Card>
          <CardHeader className="pb-3">
            <CardDescription>Total Tags</CardDescription>
            <CardTitle className="text-3xl">{totalCount}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-xs text-muted-foreground">
              Defined tag categories
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardDescription>With Auto-Tag Rules</CardDescription>
            <CardTitle className="text-3xl text-primary">
              {tags.filter(t => t.rule_type).length}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-xs text-muted-foreground">
              Tags with regex or IP range rules
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardDescription>Tagged Assets</CardDescription>
            <CardTitle className="text-3xl text-info">
              {tags.reduce((sum, t) => sum + t.asset_count, 0)}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-xs text-muted-foreground">
              Total tag applications
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Actions Bar */}
      <Card>
        <CardContent className="!pt-6 pb-6">
          <div className="flex items-center justify-between flex-wrap gap-4">
            <div className="flex items-center gap-3">
              <Button onClick={() => { resetForm(); setShowCreateModal(true); }}>
                + Create Tag
              </Button>
              <Button
                variant="outline"
                onClick={handleRunAutoTagAll}
                disabled={!!runningAutoTag}
                loading={runningAutoTag === "all"}
              >
                {runningAutoTag === "all" ? "Running..." : "Run All Auto-Tag Rules"}
              </Button>
            </div>
            <Button variant="outline" onClick={loadTags} disabled={loading}>
              {loading ? "Refreshing..." : "Refresh"}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Error Display */}
      {error && (
        <Card className="border-destructive bg-destructive/5">
          <CardContent className="py-4">
            <div className="text-destructive flex items-center gap-2">
              <span>⚠️</span>
              <span>{error}</span>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Tags Table */}
      <Card>
        <CardHeader>
          <CardTitle>Tags ({tags.length})</CardTitle>
          <CardDescription>
            Configure tags and auto-tagging rules for your assets
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="py-12">
              <LoadingSpinner size="lg" />
            </div>
          ) : tags.length === 0 ? (
            <EmptyState
              icon="🏷️"
              title="No tags defined"
              description="Create your first tag to start categorizing assets"
              action={
                <Button onClick={() => { resetForm(); setShowCreateModal(true); }}>
                  Create First Tag
                </Button>
              }
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Tag</TableHead>
                  <TableHead>Importance</TableHead>
                  <TableHead>Auto-Tag Rule</TableHead>
                  <TableHead>Assets</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {tags.map((tag) => (
                  <TableRow key={tag.id}>
                    <TableCell>
                      <div className="flex items-center gap-3">
                        <div
                          className="w-4 h-4 rounded-full ring-2 ring-offset-2 ring-offset-background"
                          style={{ backgroundColor: tag.color || "#6366f1", ringColor: tag.color || "#6366f1" }}
                        />
                        <div>
                          <div className="font-medium">{tag.name}</div>
                          {tag.description && (
                            <div className="text-sm text-muted-foreground truncate max-w-xs">
                              {tag.description}
                            </div>
                          )}
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <ImportanceShields count={tag.importance} />
                        <span className="text-xs text-muted-foreground">
                          ({tag.importance}/5)
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>
                      {tag.rule_type ? (
                        <div className="space-y-1">
                          <Badge variant={tag.rule_type === "regex" ? "info" : "secondary"}>
                            {tag.rule_type === "regex" ? "Regex" : "IP Range"}
                          </Badge>
                          <code className="block text-xs bg-muted px-2 py-1 rounded font-mono truncate max-w-xs">
                            {tag.rule_value}
                          </code>
                        </div>
                      ) : (
                        <span className="text-muted-foreground text-sm">Manual only</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <Badge variant="secondary" className="font-mono">
                        {tag.asset_count}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-2">
                        {tag.rule_type && (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleRunAutoTag(tag.id)}
                            disabled={!!runningAutoTag}
                            loading={runningAutoTag === tag.id}
                          >
                            {runningAutoTag === tag.id ? "Running..." : "Auto-Tag"}
                          </Button>
                        )}
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => openEditModal(tag)}
                        >
                          Edit
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setDeletingTag(tag)}
                          className="text-destructive hover:bg-destructive/10"
                        >
                          Delete
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Create Modal */}
      <Modal
        isOpen={showCreateModal}
        onClose={() => { setShowCreateModal(false); resetForm(); }}
        title="Create New Tag"
        size="lg"
      >
        <TagForm
          formData={formData}
          setFormData={setFormData}
          formError={formError}
          submitting={submitting}
          onSubmit={handleCreate}
          onCancel={() => { setShowCreateModal(false); resetForm(); }}
          submitLabel="Create Tag"
        />
      </Modal>

      {/* Edit Modal */}
      <Modal
        isOpen={!!editingTag}
        onClose={() => { setEditingTag(null); resetForm(); }}
        title="Edit Tag"
        size="lg"
      >
        <TagForm
          formData={formData}
          setFormData={setFormData}
          formError={formError}
          submitting={submitting}
          onSubmit={handleUpdate}
          onCancel={() => { setEditingTag(null); resetForm(); }}
          submitLabel="Save Changes"
        />
      </Modal>

      {/* Delete Confirmation Modal */}
      <Modal
        isOpen={!!deletingTag}
        onClose={() => setDeletingTag(null)}
        title="Delete Tag"
      >
        <div className="space-y-4">
          <p className="text-muted-foreground">
            Are you sure you want to delete the tag <strong>&quot;{deletingTag?.name}&quot;</strong>?
          </p>
          {deletingTag && deletingTag.asset_count > 0 && (
            <div className="p-3 bg-warning/10 rounded-lg text-warning text-sm">
              ⚠️ This tag is applied to {deletingTag.asset_count} asset(s). They will be untagged.
            </div>
          )}
          <div className="flex justify-end gap-3">
            <Button variant="outline" onClick={() => setDeletingTag(null)}>
              Cancel
            </Button>
            <Button
              onClick={handleDelete}
              disabled={submitting}
              loading={submitting}
              className="bg-destructive hover:bg-destructive/90"
            >
              Delete Tag
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}

// Tag Form Component
function TagForm({
  formData,
  setFormData,
  formError,
  submitting,
  onSubmit,
  onCancel,
  submitLabel,
}: {
  formData: TagCreate;
  setFormData: (data: TagCreate) => void;
  formError: string | null;
  submitting: boolean;
  onSubmit: () => void;
  onCancel: () => void;
  submitLabel: string;
}) {
  return (
    <div className="space-y-6">
      {formError && (
        <div className="p-3 bg-destructive/10 rounded-lg text-destructive text-sm">
          {formError}
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-2">
        <Input
          label="Tag Name *"
          placeholder="e.g., Production, High-Priority, External"
          value={formData.name}
          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
        />
        <div>
          <label className="block text-sm font-medium text-foreground mb-1.5">Color</label>
          <div className="flex items-center gap-2">
            <input
              type="color"
              value={formData.color}
              onChange={(e) => setFormData({ ...formData, color: e.target.value })}
              className="h-10 w-16 rounded border border-input cursor-pointer"
            />
            <div className="flex gap-1 flex-wrap">
              {DEFAULT_COLORS.map((color) => (
                <button
                  key={color}
                  type="button"
                  className={`w-6 h-6 rounded-full border-2 transition-transform hover:scale-110 ${
                    formData.color === color ? "border-foreground scale-110" : "border-transparent"
                  }`}
                  style={{ backgroundColor: color }}
                  onClick={() => setFormData({ ...formData, color })}
                />
              ))}
            </div>
          </div>
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-foreground mb-1.5">Description</label>
        <textarea
          className="flex w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring min-h-[80px]"
          placeholder="Optional description for this tag..."
          value={formData.description || ""}
          onChange={(e) => setFormData({ ...formData, description: e.target.value })}
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-foreground mb-1.5">
          Default Importance: {formData.importance}/5
        </label>
        <div className="flex items-center gap-4">
          <input
            type="range"
            min={1}
            max={5}
            value={formData.importance}
            onChange={(e) => setFormData({ ...formData, importance: Number(e.target.value) })}
            className="flex-1 h-2 accent-primary"
          />
          <div className="flex items-center gap-0.5">
            {Array.from({ length: 5 }).map((_, i) => (
              <svg
                key={i}
                className={`w-5 h-5 ${i < (formData.importance || 0) ? "text-primary" : "text-muted-foreground/30"}`}
                viewBox="0 0 24 24"
                fill="currentColor"
              >
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            ))}
          </div>
        </div>
        <p className="text-xs text-muted-foreground mt-1">
          This importance value will be applied to assets when tagged
        </p>
      </div>

      <div className="border-t border-border pt-4">
        <h4 className="font-medium mb-3">Auto-Tagging Rule (Optional)</h4>
        <div className="grid gap-4 md:grid-cols-2">
          <Select
            label="Rule Type"
            value={formData.rule_type || ""}
            onChange={(e) => setFormData({ 
              ...formData, 
              rule_type: e.target.value as "regex" | "ip_range" | undefined || undefined 
            })}
          >
            <option value="">No auto-tagging (manual only)</option>
            <option value="regex">Regex (for domains, ASNs, certificates, orgs)</option>
            <option value="ip_range">IP Range (CIDR notation for IPs)</option>
          </Select>
          <Input
            label={formData.rule_type === "ip_range" ? "CIDR Range(s)" : "Regex Pattern"}
            placeholder={
              formData.rule_type === "ip_range"
                ? "e.g., 10.0.0.0/8, 192.168.1.0/24"
                : "e.g., .*\\.prod\\.example\\.com$"
            }
            value={formData.rule_value || ""}
            onChange={(e) => setFormData({ ...formData, rule_value: e.target.value })}
            disabled={!formData.rule_type}
          />
        </div>
        {formData.rule_type && (
          <div className="mt-2 p-3 bg-muted rounded-lg text-sm">
            {formData.rule_type === "regex" ? (
              <div>
                <strong>Regex:</strong> Will match against domain names, ASN numbers, certificate subjects, and organization names.
                <br />
                <span className="text-muted-foreground">Example: <code>.*\\.staging\\.</code> matches all staging subdomains</span>
              </div>
            ) : (
              <div>
                <strong>IP Range:</strong> Will match IP addresses within the specified CIDR range(s).
                <br />
                <span className="text-muted-foreground">Use comma-separated values for multiple ranges: <code>10.0.0.0/8, 172.16.0.0/12</code></span>
              </div>
            )}
          </div>
        )}
      </div>

      <div className="flex justify-end gap-3 pt-4 border-t border-border">
        <Button variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button onClick={onSubmit} disabled={submitting} loading={submitting}>
          {submitLabel}
        </Button>
      </div>
    </div>
  );
}

