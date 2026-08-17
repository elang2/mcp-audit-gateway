export type LogLevel = "debug" | "info" | "warn" | "error";

const LEVEL_PRIORITY: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

export interface LogEntry {
  timestamp: string;
  level: LogLevel;
  component: string;
  message: string;
  [key: string]: unknown;
}

export interface LoggerOptions {
  component: string;
  level?: LogLevel;
  output?: (line: string) => void;
}

export class Logger {
  private component: string;
  private minLevel: number;
  private output: (line: string) => void;

  constructor(options: LoggerOptions) {
    this.component = options.component;
    this.minLevel = LEVEL_PRIORITY[options.level ?? "info"];
    this.output = options.output ?? ((line: string) => process.stderr.write(line + "\n"));
  }

  debug(message: string, context?: Record<string, unknown>): void {
    this.log("debug", message, context);
  }

  info(message: string, context?: Record<string, unknown>): void {
    this.log("info", message, context);
  }

  warn(message: string, context?: Record<string, unknown>): void {
    this.log("warn", message, context);
  }

  error(message: string, context?: Record<string, unknown>): void {
    this.log("error", message, context);
  }

  private log(level: LogLevel, message: string, context?: Record<string, unknown>): void {
    if (LEVEL_PRIORITY[level] < this.minLevel) return;

    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      component: this.component,
      message,
      ...context,
    };

    this.output(JSON.stringify(entry));
  }

  child(overrides: Partial<LoggerOptions>): Logger {
    return new Logger({
      component: overrides.component ?? this.component,
      level: overrides.level ?? (Object.keys(LEVEL_PRIORITY) as LogLevel[])[this.minLevel],
      output: overrides.output ?? this.output,
    });
  }
}
