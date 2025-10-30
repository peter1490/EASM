# Frontend Utilities

## Logger

The logger utility provides environment-aware logging that respects the `NEXT_PUBLIC_LOG_LEVEL` environment variable.

### Configuration

The log level is controlled by the `LOG_LEVEL` variable in your `.env` file, which is automatically mapped to `NEXT_PUBLIC_LOG_LEVEL` in the frontend via Docker Compose.

Valid log levels (in order of verbosity):
- `TRACE` - Most verbose, logs everything
- `DEBUG` - Debug information for development
- `INFO` - General informational messages (default)
- `WARN` - Warning messages
- `ERROR` - Error messages only
- `NONE` - Disable all logging

### Usage

```typescript
import { logger } from '@/utils/logger';

// Trace-level logging (most verbose)
logger.trace('Detailed trace information', { data: someData });

// Debug-level logging
logger.debug('Debug info for development', debugObject);

// Info-level logging
logger.info('User logged in successfully', { userId: user.id });

// Warning-level logging
logger.warn('API rate limit approaching', { remaining: 10 });

// Error-level logging
logger.error('Failed to load data', error);
```

### Examples

```typescript
// In a React component
import { logger } from '@/utils/logger';

export default function MyComponent() {
  useEffect(() => {
    logger.debug('Component mounted');
    
    fetchData()
      .then(data => {
        logger.info('Data loaded successfully', { count: data.length });
      })
      .catch(error => {
        logger.error('Failed to fetch data', error);
      });
      
    return () => {
      logger.debug('Component unmounted');
    };
  }, []);
  
  return <div>My Component</div>;
}
```

```typescript
// In an API handler
import { logger } from '@/utils/logger';

export async function fetchUsers() {
  logger.debug('Fetching users from API');
  
  try {
    const response = await fetch('/api/users');
    
    if (!response.ok) {
      logger.warn('API returned non-OK status', { 
        status: response.status 
      });
    }
    
    const users = await response.json();
    logger.info('Successfully fetched users', { count: users.length });
    
    return users;
  } catch (error) {
    logger.error('Failed to fetch users', error);
    throw error;
  }
}
```

### Environment Configuration

In development (default: INFO):
```env
LOG_LEVEL=DEBUG
```

In production (default: WARN):
```env
LOG_LEVEL=WARN
```

This ensures minimal console output in production while maintaining detailed logs in development.

