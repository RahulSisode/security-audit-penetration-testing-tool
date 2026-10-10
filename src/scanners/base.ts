import { SecurityFinding, ScannerExecutionResult, ScanOptions } from '../core/types';

export interface IScanner {
  readonly id: string;
  readonly name: string;
  isAvailable(): Promise<boolean>;
  getVersion(): Promise<string>;
  scan(options: ScanOptions): Promise<{
    findings: SecurityFinding[];
    executionResult: ScannerExecutionResult;
  }>;
}

export abstract class BaseScanner implements IScanner {
  public abstract readonly id: string;
  public abstract readonly name: string;

  public abstract isAvailable(): Promise<boolean>;
  public abstract getVersion(): Promise<string>;
  public abstract scan(options: ScanOptions): Promise<{
    findings: SecurityFinding[];
    executionResult: ScannerExecutionResult;
  }>;
}
