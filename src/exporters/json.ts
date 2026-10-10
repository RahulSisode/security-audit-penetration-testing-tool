import { ScanResult } from '../core/types';

export class JSONExporter {
  public static export(result: ScanResult): string {
    return JSON.stringify(result, null, 2);
  }
}
