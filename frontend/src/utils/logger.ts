/**
 * Logging utility that respects NEXT_PUBLIC_LOG_LEVEL environment variable
 * Valid log levels: TRACE, DEBUG, INFO, WARN, ERROR
 */

enum LogLevel {
  TRACE = 0,
  DEBUG = 1,
  INFO = 2,
  WARN = 3,
  ERROR = 4,
  NONE = 5,
}

const LOG_LEVEL_MAP: Record<string, LogLevel> = {
  TRACE: LogLevel.TRACE,
  DEBUG: LogLevel.DEBUG,
  INFO: LogLevel.INFO,
  WARN: LogLevel.WARN,
  WARNING: LogLevel.WARN,
  ERROR: LogLevel.ERROR,
  NONE: LogLevel.NONE,
};

// Get configured log level from environment variable
const getConfiguredLogLevel = (): LogLevel => {
  const envLogLevel = process.env.NEXT_PUBLIC_LOG_LEVEL?.toUpperCase() || 'INFO';
  return LOG_LEVEL_MAP[envLogLevel] ?? LogLevel.INFO;
};

const currentLogLevel = getConfiguredLogLevel();

/**
 * Logger class with environment-aware log level filtering
 */
class Logger {
  private shouldLog(level: LogLevel): boolean {
    return level >= currentLogLevel;
  }

  /**
   * Log trace-level messages (most verbose)
   */
  trace(...args: unknown[]): void {
    if (this.shouldLog(LogLevel.TRACE)) {
      console.log('[TRACE]', ...args);
    }
  }

  /**
   * Log debug-level messages
   */
  debug(...args: unknown[]): void {
    if (this.shouldLog(LogLevel.DEBUG)) {
      console.log('[DEBUG]', ...args);
    }
  }

  /**
   * Log info-level messages
   */
  info(...args: unknown[]): void {
    if (this.shouldLog(LogLevel.INFO)) {
      console.info('[INFO]', ...args);
    }
  }

  /**
   * Log warning-level messages
   */
  warn(...args: unknown[]): void {
    if (this.shouldLog(LogLevel.WARN)) {
      console.warn('[WARN]', ...args);
    }
  }

  /**
   * Log error-level messages
   */
  error(...args: unknown[]): void {
    if (this.shouldLog(LogLevel.ERROR)) {
      console.error('[ERROR]', ...args);
    }
  }

  /**
   * Get the current configured log level as a string
   */
  getLogLevel(): string {
    return Object.keys(LOG_LEVEL_MAP).find(
      key => LOG_LEVEL_MAP[key] === currentLogLevel
    ) || 'INFO';
  }
}

// Export singleton instance
export const logger = new Logger();

// Export default
export default logger;

