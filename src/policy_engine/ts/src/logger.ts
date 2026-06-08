// Leveled logging, a port of ../../common/logger.go. Controlled by the
// POLICY_ENGINE_LOG_LEVEL env var: trace, debug, info (default), warn, error.

export enum LogLevel {
  Trace = 0,
  Debug = 1,
  Info = 2,
  Warn = 3,
  Error = 4,
}

function currentLevel(): LogLevel {
  const v = (Deno.env.get("POLICY_ENGINE_LOG_LEVEL") ?? "info").toLowerCase();
  switch (v) {
    case "trace":
      return LogLevel.Trace;
    case "debug":
      return LogLevel.Debug;
    case "warn":
      return LogLevel.Warn;
    case "error":
      return LogLevel.Error;
    default:
      return LogLevel.Info;
  }
}

function log(level: LogLevel, tag: string, msg: string, args: unknown[]): void {
  if (level < currentLevel()) return;
  const formatted = args.length > 0 ? sprintf(msg, args) : msg;
  console.error(`[${tag}] ${formatted}`);
}

// Minimal printf-style formatter supporting %s, %d, %v, %q, %w.
function sprintf(fmt: string, args: unknown[]): string {
  let i = 0;
  return fmt.replace(/%[sdvqw%]/g, (m) => {
    if (m === "%%") return "%";
    const a = args[i++];
    if (m === "%q") return JSON.stringify(String(a));
    if (a instanceof Error) return a.message;
    if (typeof a === "object") return JSON.stringify(a);
    return String(a);
  });
}

export const Trace = (msg: string, ...args: unknown[]) => log(LogLevel.Trace, "TRACE", msg, args);
export const Debug = (msg: string, ...args: unknown[]) => log(LogLevel.Debug, "DEBUG", msg, args);
export const Info = (msg: string, ...args: unknown[]) => log(LogLevel.Info, "INFO", msg, args);
export const Warn = (msg: string, ...args: unknown[]) => log(LogLevel.Warn, "WARN", msg, args);
export const LogError = (msg: string, ...args: unknown[]) =>
  log(LogLevel.Error, "ERROR", msg, args);
