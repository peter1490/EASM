# EASM Frontend

Modern Next.js 15 frontend for the External Attack Surface Management platform.

## Features

- **Real-time Dashboard**: Live scan status updates
- **Asset Management**: View and manage discovered assets with confidence scoring
- **Seed Management**: Configure discovery seeds (domains, CIDRs, ASNs, organizations)
- **Scan History**: Track and review scan results
- **Modern UI**: Built with Tailwind CSS 4 and React 19

## Getting Started

### Prerequisites

- Node.js 20 or later
- Backend API running on `http://localhost:8000` (or set `NEXT_PUBLIC_API_BASE`)

### Development

```bash
# Install dependencies
npm install

# Run development server
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) to see the application.

### Production Build

```bash
# Build for production
npm run build

# Start production server
npm start
```

## Configuration

Environment variables:

- `NEXT_PUBLIC_API_BASE`: Backend API URL (default: `http://localhost:8000`)

## Project Structure

```
src/
├── app/
│   ├── page.tsx              # Dashboard (scan management)
│   ├── assets/               # Assets view
│   │   └── page.tsx
│   ├── seeds/                # Seed management
│   │   └── page.tsx
│   ├── scan/[id]/            # Individual scan detail
│   │   └── page.tsx
│   ├── api.ts                # API client and types
│   ├── layout.tsx            # Root layout
│   └── globals.css           # Global styles
└── ...
```

## API Integration

The frontend communicates with the Rust backend API. See `src/app/api.ts` for the complete API client implementation.

Main API endpoints:
- `/api/scans` - Scan management
- `/api/seeds` - Seed configuration
- `/api/assets` - Asset inventory
- `/api/discovery/run` - Trigger discovery

## Technology Stack

- **Framework**: Next.js 15 (App Router)
- **Language**: TypeScript 5
- **Styling**: Tailwind CSS 4
- **UI**: React 19
- **Build Tool**: Turbopack (dev mode)
