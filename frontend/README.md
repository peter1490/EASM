# EASM Frontend

Enterprise-grade External Attack Surface Management platform frontend built with Next.js 15, React 19, and modern UI components.

## 🎨 Features

### Professional UI/UX
- **Modern Design System**: Custom color palette optimized for security applications
- **Dark Mode Support**: Automatic theme switching based on system preferences
- **Responsive Design**: Fully responsive layouts for desktop, tablet, and mobile
- **Accessibility**: WCAG-compliant components with keyboard navigation support

### Core Features
- **Dashboard**: Real-time metrics, stats cards, and recent scan activity
- **Asset Management**: Advanced filtering, search, and confidence-based asset tracking
- **Seed Configuration**: Intuitive seed management with type-specific inputs
- **Scan Details**: Tabbed interface with findings visualization and raw data view
- **Real-time Updates**: Auto-refreshing data with polling for live status updates

### UI Components
- **Reusable Components**: Button, Card, Badge, Input, Select, Table, and more
- **Loading States**: Elegant loading spinners and skeleton screens
- **Empty States**: Contextual empty state messages with calls-to-action
- **Error Handling**: User-friendly error messages and retry mechanisms
- **Animations**: Smooth transitions and fade-in effects

## 🚀 Getting Started

### Prerequisites

- Node.js 20 or later
- Backend API running on `http://localhost:8000` (or configure `NEXT_PUBLIC_API_BASE`)

### Installation

```bash
# Install dependencies
npm install
```

### Development

```bash
# Run development server with Turbopack
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) to view the application.

### Production Build

```bash
# Build for production
npm run build

# Start production server
npm start
```

## 📁 Project Structure

```
src/
├── app/
│   ├── page.tsx                    # Dashboard with metrics and scan creation
│   ├── assets/
│   │   └── page.tsx               # Asset inventory with filtering
│   ├── seeds/
│   │   └── page.tsx               # Seed management and discovery
│   ├── scan/[id]/
│   │   └── page.tsx               # Detailed scan view with tabs
│   ├── api.ts                     # API client and TypeScript types
│   ├── layout.tsx                 # Root layout with sidebar
│   └── globals.css                # Global styles and design tokens
│
├── components/
│   ├── ui/
│   │   ├── Button.tsx             # Button component with variants
│   │   ├── Card.tsx               # Card components (Header, Content, etc.)
│   │   ├── Badge.tsx              # Status badges with color variants
│   │   ├── Input.tsx              # Form input with label and error
│   │   ├── Select.tsx             # Dropdown select component
│   │   ├── Table.tsx              # Table components (Header, Row, Cell)
│   │   ├── EmptyState.tsx         # Empty state component
│   │   └── LoadingSpinner.tsx     # Loading indicator
│   ├── Sidebar.tsx                # Main navigation sidebar
│   └── Header.tsx                 # Page header component
│
└── ...
```

## 🎨 Design System

### Color Palette

The application uses a professional security-focused color palette:

- **Primary**: Blue (`#2563eb`) - Main actions and interactive elements
- **Success**: Green (`#10b981`) - Completed states and high confidence
- **Warning**: Amber (`#f59e0b`) - In-progress states and medium confidence
- **Error/Destructive**: Red (`#ef4444`) - Failed states and critical issues
- **Info**: Blue (`#3b82f6`) - Informational elements
- **Muted**: Gray tones for secondary content

### Typography

- **Font Family**: Geist Sans (primary), Geist Mono (code)
- **Font Sizes**: Consistent scale from `text-xs` to `text-3xl`
- **Font Weights**: Regular (400), Medium (500), Semibold (600), Bold (700)

### Spacing

Consistent spacing using Tailwind's spacing scale (1-12, with larger increments for layout)

## 🔧 Configuration

### Environment Variables

Create a `.env.local` file in the frontend directory:

```env
NEXT_PUBLIC_API_BASE=http://localhost:8000
```

Available variables:
- `NEXT_PUBLIC_API_BASE`: Backend API URL (default: `http://localhost:8000`)

## 📊 Pages Overview

### Dashboard (`/`)

The main landing page featuring:
- **Statistics Cards**: Total scans, completed, active, and findings count
- **Scan Creation Form**: Create new scans with advanced options
- **Recent Scans Table**: Latest scan operations with quick access

### Assets (`/assets`)

Asset inventory management:
- **Stats Overview**: Total assets, domains, IPs, and high-confidence assets
- **Advanced Filtering**: Search, type filter, and confidence threshold slider
- **Asset Tracking**: Visual representation of asset discovery paths
- **Real-time Discovery**: Live updates when discovery is running

### Seeds (`/seeds`)

Seed configuration for asset discovery:
- **Seed Type Selection**: Support for domains, CIDRs, ASNs, organizations, keywords
- **Discovery Controls**: Run discovery with configurable confidence threshold
- **Seed Management**: Add, view, and delete seeds

### Scan Details (`/scan/[id]`)

Detailed scan information with tabs:
- **Overview Tab**: Scan metadata and summary statistics
- **Findings Tab**: Categorized findings with severity indicators
- **Raw Data Tab**: Complete JSON response for debugging

## 🔨 Development

### Component Development

All UI components are built with:
- TypeScript for type safety
- `forwardRef` for ref forwarding
- Consistent prop interfaces
- Tailwind CSS for styling

Example:
```tsx
import Button from "@/components/ui/Button";

<Button 
  variant="primary" 
  size="lg" 
  loading={isLoading}
  onClick={handleClick}
>
  Click Me
</Button>
```

### API Integration

The API client (`src/app/api.ts`) provides typed functions for all backend endpoints:

```typescript
import { createScan, listScans, listAssets } from "@/app/api";

// Create a scan
const scan = await createScan("example.com", "My scan", { 
  enumerate_subdomains: true 
});

// List assets
const assets = await listAssets(0.7); // min confidence 0.7
```

## 🎯 Best Practices

### State Management
- Use React hooks (`useState`, `useEffect`) for component state
- Implement proper cleanup in `useEffect` for timers and subscriptions
- Use `useTransition` for non-blocking state updates

### Performance
- Real-time updates use polling with automatic cleanup
- Tables and lists are optimized for large datasets
- Images and assets are optimized with Next.js built-in optimization

### Accessibility
- All interactive elements have proper focus states
- Semantic HTML for better screen reader support
- Color contrast ratios meet WCAG AA standards
- Keyboard navigation support throughout

## 🚢 Deployment

### Docker

The frontend includes a Dockerfile for containerized deployment:

```bash
docker build -t easm-frontend .
docker run -p 3000:3000 -e NEXT_PUBLIC_API_BASE=http://api:8000 easm-frontend
```

### Vercel

Deploy to Vercel with one click:

```bash
vercel deploy
```

Set the `NEXT_PUBLIC_API_BASE` environment variable in your Vercel project settings.

## 📝 Technology Stack

- **Framework**: Next.js 15 (App Router)
- **Language**: TypeScript 5
- **Styling**: Tailwind CSS 4
- **UI**: React 19
- **Build Tool**: Turbopack (development)
- **Fonts**: Geist Sans & Geist Mono

## 🤝 Contributing

When contributing to the frontend:

1. Follow the existing component patterns
2. Use TypeScript for all new files
3. Ensure components are reusable and well-typed
4. Add proper error handling and loading states
5. Test responsive behavior on multiple screen sizes
6. Run `npm run lint` before committing

## 📄 License

Part of the EASM (External Attack Surface Management) project.

---

Built with ❤️ using Next.js and modern web technologies.
