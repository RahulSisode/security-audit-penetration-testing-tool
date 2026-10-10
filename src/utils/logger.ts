import { redactSecrets } from '../core/redaction';

export class SafeLogger {
  private prefix: string;

  constructor(prefix: string = '[SentinelSecurity]') {
    this.prefix = prefix;
  }

  public info(message: string, ...args: any[]): void {
    const sanitizedMsg = redactSecrets(message);
    console.log(`${this.prefix} [INFO] ${sanitizedMsg}`, ...this.sanitizeArgs(args));
  }

  public warn(message: string, ...args: any[]): void {
    const sanitizedMsg = redactSecrets(message);
    console.warn(`${this.prefix} [WARN] ${sanitizedMsg}`, ...this.sanitizeArgs(args));
  }

  public error(message: string, ...args: any[]): void {
    const sanitizedMsg = redactSecrets(message);
    console.error(`${this.prefix} [ERROR] ${sanitizedMsg}`, ...this.sanitizeArgs(args));
  }

  public debug(message: string, ...args: any[]): void {
    const sanitizedMsg = redactSecrets(message);
    console.debug(`${this.prefix} [DEBUG] ${sanitizedMsg}`, ...this.sanitizeArgs(args));
  }

  private sanitizeArgs(args: any[]): any[] {
    return args.map(arg => {
      if (typeof arg === 'string') {
        return redactSecrets(arg);
      }
      if (typeof arg === 'object' && arg !== null) {
        try {
          return JSON.parse(redactSecrets(JSON.stringify(arg)));
        } catch {
          return '[Unserializable Object]';
        }
      }
      return arg;
    });
  }
}

export const logger = new SafeLogger();
