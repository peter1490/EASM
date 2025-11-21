# Finding Filter - Quick Start Guide

## 🚀 Quick Start

### 1. Apply Database Migration
```bash
cd backend
sqlx migrate run
# or with docker-compose
docker-compose exec backend sqlx migrate run
```

### 2. Start the Application
```bash
# Terminal 1: Backend
cd backend
cargo run

# Terminal 2: Frontend
cd frontend
npm run dev
```

### 3. Access the Findings Page
Navigate to: `http://localhost:3000/findings`

## 📡 API Endpoints

### Get All Findings (No Filters)
```bash
curl "http://localhost:8000/api/findings/filter?limit=50"
```

### Filter by Finding Type
```bash
curl "http://localhost:8000/api/findings/filter?finding_types=port_scan,dns_resolution"
```

### Search Text
```bash
curl "http://localhost:8000/api/findings/filter?search_text=example.com"
```

### Date Range Filter
```bash
curl "http://localhost:8000/api/findings/filter?created_after=2024-01-01T00:00:00Z&created_before=2024-12-31T23:59:59Z"
```

### Get Available Finding Types
```bash
curl "http://localhost:8000/api/findings/types"
```

### Complex Filter Example
```bash
curl -G "http://localhost:8000/api/findings/filter" \
  --data-urlencode "finding_types=port_scan,http_probe" \
  --data-urlencode "search_text=443" \
  --data-urlencode "sort_by=created_at" \
  --data-urlencode "sort_direction=desc" \
  --data-urlencode "limit=20" \
  --data-urlencode "offset=0"
```

## 🎨 UI Features

### Filter Panel
- **Text Search**: Quick search across all finding data
- **Type Filter**: Multi-select checkboxes for finding types
- **Scan Filter**: Filter by specific scans
- **Date Range**: From/To datetime pickers
- **Sorting**: By date or type, ascending or descending
- **Active Filter Badge**: Shows count of active filters

### Findings List
- **Formatted Display**: Clean card-based layout
- **Finding Renderer**: Specialized rendering for each finding type
- **Pagination**: Navigate through large result sets
- **Empty States**: Helpful messages when no results
- **Loading States**: Visual feedback during API calls

## 🔍 Filter Options

| Parameter | Type | Description | Example |
|-----------|------|-------------|---------|
| `finding_types` | string | Comma-separated finding types | `port_scan,dns_resolution` |
| `scan_ids` | string | Comma-separated UUIDs | `uuid1,uuid2` |
| `created_after` | string | ISO 8601 datetime | `2024-01-01T00:00:00Z` |
| `created_before` | string | ISO 8601 datetime | `2024-12-31T23:59:59Z` |
| `search_text` | string | Full-text search query | `example.com` |
| `sort_by` | string | Sort field | `created_at`, `finding_type` |
| `sort_direction` | string | Sort order | `asc`, `desc` |
| `limit` | number | Results per page (max 1000) | `50` |
| `offset` | number | Pagination offset | `0`, `50`, `100` |

## 🎯 Common Finding Types

Based on your scan configuration, you may see:
- `subdomain_enumeration` - Discovered subdomains
- `dns_resolution` - DNS lookup results
- `port_scan` - Open port findings
- `http_probe` - HTTP service information
- `tls_analysis` - TLS/SSL certificate data
- `reverse_dns` - Reverse DNS lookups
- `threat_intelligence` - Threat intel results
- `cidr_expansion` - CIDR range expansion

## 💡 Usage Tips

### Efficient Filtering
1. **Start Broad**: Begin with type filters to narrow down results
2. **Add Specifics**: Use text search for specific targets
3. **Date Ranges**: Use recent date filters for active investigations
4. **Combine Filters**: Mix multiple criteria for precise results

### Performance
- Use pagination for large result sets
- Limit results to what you need (default: 100, max: 1000)
- Date range filters are highly optimized with indexes
- Type filters leverage composite indexes for speed

### Best Practices
- **Regular Scans**: Keep running scans to populate findings
- **Filter Presets**: Use common filter combinations regularly
- **Export Data**: Consider implementing CSV export for reporting
- **Monitor Types**: Use the types endpoint to see what's available

## 🐛 Troubleshooting

### No Findings Showing
1. Check if scans have been run: `GET /api/scans`
2. Verify findings exist: `GET /api/findings/filter?limit=1`
3. Check filter criteria isn't too restrictive
4. Look for error messages in browser console

### Slow Queries
1. Verify database indexes are applied: Check `002_finding_filter_indexes.sql`
2. Check if too many results: Reduce limit or add more filters
3. Monitor database query performance

### Date Range Not Working
1. Ensure ISO 8601 format: `YYYY-MM-DDTHH:MM:SSZ`
2. Use UTC timezone (Z suffix)
3. Check created_after is before created_before

## 📊 Example Response

```json
{
  "findings": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "scan_id": "660e8400-e29b-41d4-a716-446655440000",
      "finding_type": "port_scan",
      "data": {
        "ip": "192.168.1.1",
        "open_ports": [80, 443, 22],
        "count": 3
      },
      "created_at": "2024-10-31T10:30:00Z"
    }
  ],
  "total_count": 1,
  "limit": 50,
  "offset": 0
}
```

## 🔐 Security Notes

- All queries use parameterized SQL (no SQL injection risk)
- Input validation on all parameters
- Result limiting prevents DoS attacks
- Type safety in Rust backend
- CORS configured appropriately

## 🚦 Next Steps

1. **Run Your First Filter**: Navigate to `/findings` and try the filter panel
2. **Explore Finding Types**: Click through different types to see varied data
3. **Test Pagination**: Navigate through multiple pages of results
4. **Try Advanced Filters**: Combine multiple filter criteria
5. **Check Performance**: Monitor query times with browser DevTools

---

**Need Help?** Check the full documentation in `FINDING_FILTER_IMPLEMENTATION.md`

