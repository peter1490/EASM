# Asset Discovery Path Tracing - Analysis Report

## Executive Summary

The asset discovery path tracing system has been analyzed for correctness and performance. Several issues were identified ranging from critical correctness bugs to performance optimizations. This report details all findings and provides recommended fixes.

---

## System Overview

The path tracing system consists of:
1. **Database Schema**: `seed_id` and `parent_id` columns in the `assets` table with indexes
2. **Repository Layer**: Recursive CTE query to traverse parent relationships
3. **Service Layer**: Asset discovery with lineage tracking
4. **API Layer**: REST endpoint to fetch asset paths
5. **Frontend**: React Flow visualization of discovery paths

---

## Critical Issues (Must Fix)

### 1. ❌ **Broken Lineage Chain During Asset Merge**

**Location**: `backend/src/repositories/asset_repo.rs:89`

**Problem**: When merging an existing asset that has NO lineage info with new data that HAS lineage info, the code preserves the existing NULL values:

```sql
UPDATE assets
SET ... seed_id = COALESCE(assets.seed_id, $5), parent_id = COALESCE(assets.parent_id, $6)
```

This means once an asset is created without lineage, it can never get lineage added later. This breaks the entire path tracing system.

**Impact**: 
- Assets discovered before lineage implementation will never show paths
- If discovery order matters (e.g., asset created from one source, then linked from another), lineage is lost
- Recursive discovery may create disconnected graphs

**Fix**: Change merge logic to UPDATE lineage if provided:
```sql
UPDATE assets
SET ... seed_id = COALESCE($5, assets.seed_id), parent_id = COALESCE($6, assets.parent_id)
```

---

### 2. ⚠️ **Infinite Loop Risk - No Cycle Detection**

**Location**: `backend/src/repositories/asset_repo.rs:324-363`

**Problem**: The recursive CTE has no cycle detection:

```sql
WITH RECURSIVE asset_path AS (
    SELECT ... WHERE id = $1
    UNION ALL
    SELECT ... FROM assets p INNER JOIN asset_path ap ON p.id = ap.parent_id
)
```

If there's ever a bug that creates a cycle (e.g., A → B → C → A), this query will run infinitely until timeout.

**Impact**:
- Database timeout errors
- Resource exhaustion
- Denial of service risk

**Fix**: Add cycle detection by tracking visited IDs:
```sql
WITH RECURSIVE asset_path AS (
    SELECT id, asset_type, identifier, confidence, sources, metadata, 
           created_at, updated_at, seed_id, parent_id,
           ARRAY[id] as path_ids  -- Track visited nodes
    FROM assets
    WHERE id = $1
    
    UNION ALL
    
    SELECT p.id, p.asset_type, p.identifier, p.confidence, p.sources, p.metadata,
           p.created_at, p.updated_at, p.seed_id, p.parent_id,
           ap.path_ids || p.id
    FROM assets p
    INNER JOIN asset_path ap ON p.id = ap.parent_id
    WHERE NOT (p.id = ANY(ap.path_ids))  -- Prevent cycles
)
```

---

### 3. ⚠️ **Missing Depth Limit**

**Location**: `backend/src/repositories/asset_repo.rs:324-363`

**Problem**: No depth limit in the recursive query. A very deep chain (e.g., 1000+ levels) would be slow and use excessive memory.

**Impact**:
- Slow query performance for deep hierarchies
- Memory exhaustion
- Potential database performance degradation

**Fix**: Add depth tracking and limit:
```sql
WITH RECURSIVE asset_path AS (
    SELECT ..., ARRAY[id] as path_ids, 0 as depth
    FROM assets WHERE id = $1
    
    UNION ALL
    
    SELECT ..., ap.path_ids || p.id, ap.depth + 1
    FROM assets p
    INNER JOIN asset_path ap ON p.id = ap.parent_id
    WHERE NOT (p.id = ANY(ap.path_ids)) AND ap.depth < 100
)
```

---

## Major Issues (Should Fix)

### 4. ⚠️ **Organization Assets Created Without Parent Link**

**Location**: 
- `backend/src/services/discovery_service.rs:460`
- `backend/src/services/discovery_service.rs:597`

**Problem**: When discovering organizations from certificates during recursive discovery, the code explicitly sets `parent_id: None` with comments:
```rust
parent_id: None, // Parent could be the certificate, but we don't have its ID easily here
```

This breaks the lineage chain between Certificate → Organization.

**Impact**:
- Incomplete discovery paths
- Users can't trace how organizations were discovered
- Graph visualization shows disconnected nodes

**Fix**: Lookup the certificate asset ID before creating organization, or refactor to save certificate first and pass its ID.

---

### 5. 🐛 **Inconsistent Parent Assignment in Domain Discovery**

**Location**: `backend/src/services/discovery_service.rs:714`

**Problem**: In `discover_from_domain`, subdomains are created with `parent_id` from function parameter, but this might be the root seed asset, not the immediate parent domain. The lineage should be: Seed → RootDomain → Subdomain1 → Subdomain2, but currently it's: Seed → RootDomain, Seed → Subdomain1, Seed → Subdomain2.

**Impact**:
- Flattened hierarchy instead of true tree structure
- Can't distinguish between direct subdomains and deeper levels
- Misleading path visualization

**Fix**: Pass the current domain asset ID as parent for its subdomains, not the seed's root asset.

---

## Performance Issues

### 6. 🐌 **Expensive Scan Join in Path Query**

**Location**: `backend/src/repositories/asset_repo.rs:324-363`

**Problem**: The `get_path` query includes a complex CTE to find latest scans:

```sql
LEFT JOIN (
    SELECT DISTINCT ON (LOWER(TRIM(target))) 
        id, status, created_at, LOWER(TRIM(target)) as normalized_target
    FROM scans
    ORDER BY LOWER(TRIM(target)), created_at DESC
) ls ON ls.normalized_target = LOWER(TRIM(ap.identifier))
```

This is unnecessary for path tracing and adds significant overhead, especially if the scans table is large.

**Impact**:
- Slower API response times
- Unnecessary database load
- Poor user experience for path visualization

**Fix**: Create a separate lightweight query for path tracing without scan data:
```sql
WITH RECURSIVE asset_path AS (
    SELECT id, asset_type, identifier, confidence, sources, metadata, 
           created_at, updated_at, seed_id, parent_id,
           ARRAY[id] as path_ids, 0 as depth
    FROM assets WHERE id = $1
    
    UNION ALL
    
    SELECT p.id, p.asset_type, p.identifier, p.confidence, p.sources, p.metadata,
           p.created_at, p.updated_at, p.seed_id, p.parent_id,
           ap.path_ids || p.id, ap.depth + 1
    FROM assets p
    INNER JOIN asset_path ap ON p.id = ap.parent_id
    WHERE NOT (p.id = ANY(ap.path_ids)) AND ap.depth < 100
)
SELECT id, asset_type, identifier, confidence, sources, metadata, 
       created_at, updated_at, seed_id, parent_id
FROM asset_path;
```

---

### 7. 🐌 **Missing Index Hint**

**Location**: `backend/src/repositories/asset_repo.rs:340`

**Problem**: The recursive join on `parent_id` should use the index `idx_assets_parent_id`, but there's no guarantee without query analysis.

**Impact**:
- Potentially slower queries if planner doesn't use index
- Performance degradation as asset table grows

**Fix**: Ensure index is used with query analysis (EXPLAIN ANALYZE) and consider adding covering index if needed.

---

## Minor Issues

### 8. ℹ️ **No Caching for Frequently Accessed Paths**

**Problem**: Popular assets (e.g., root domains) will have their paths queried frequently, but there's no caching.

**Impact**:
- Repeated expensive queries
- Higher database load

**Fix**: Consider adding Redis cache with TTL for path queries.

---

### 9. ℹ️ **Frontend Fallback Logic May Hide Issues**

**Location**: `frontend/src/components/AssetDiscoveryGraph.tsx:217-231`

**Problem**: If no edges are created from parent_id relationships, the frontend falls back to sequential linking:
```typescript
if (initialEdges.length === 0 && assets.length > 1) {
    for (let i = 0; i < assets.length - 1; i++) {
        // Create sequential edges
    }
}
```

This masks backend issues where parent_id relationships are missing.

**Impact**:
- Incorrect graphs shown to users
- Backend lineage bugs go unnoticed

**Fix**: Remove fallback and show a warning when lineage data is missing.

---

## Performance Benchmarks Needed

To validate performance, the following tests should be performed:

1. **Deep Chain Test**: Create a 100-level deep parent chain and measure query time
2. **Wide Tree Test**: Create 1000 assets with same parent and measure query time
3. **Large Database Test**: Test with 100K+ assets to ensure index usage
4. **Cycle Test**: Verify cycle detection works (after fix)

---

## Recommended Priority

1. **CRITICAL**: Fix lineage merge logic (#1)
2. **CRITICAL**: Add cycle detection (#2)
3. **HIGH**: Add depth limit (#3)
4. **HIGH**: Remove scan join from path query (#6)
5. **MEDIUM**: Fix organization parent linking (#4)
6. **MEDIUM**: Fix domain hierarchy (#5)
7. **LOW**: Add caching (#8)
8. **LOW**: Remove frontend fallback (#9)

---

## Test Coverage Gaps

No tests found for:
- `get_path` function
- Cycle detection
- Depth limits
- Lineage preservation during merge
- Path query performance

**Recommendation**: Add comprehensive test suite covering all edge cases.

---

## Conclusion

The asset discovery path tracing system has a solid foundation but requires critical fixes to ensure correctness and performance. The most urgent issues are:

1. Broken lineage merge logic that prevents path tracking
2. Missing cycle detection that risks infinite loops
3. Performance issues with unnecessary scan joins

Once these are addressed, the system should be robust and performant for production use.

