import { spawn, SpawnOptions } from 'child_process';

export interface SafeProcessResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  durationMs: number;
  timedOut: boolean;
  error?: Error;
}

export interface SafeProcessOptions {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  timeoutMs?: number;
  maxBufferBytes?: number;
  abortSignal?: AbortSignal;
}

/**
 * Safely executes a binary without shell interpolation.
 * Strictly uses argument arrays and handles cancellation and timeouts.
 */
export async function executeSafeProcess(
  executable: string,
  args: string[],
  options: SafeProcessOptions = {}
): Promise<SafeProcessResult> {
  const timeoutMs = options.timeoutMs || 60000;
  const maxBuffer = options.maxBufferBytes || 50 * 1024 * 1024; // 50MB
  const startTime = Date.now();

  return new Promise<SafeProcessResult>((resolve) => {
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let timer: NodeJS.Timeout | null = null;

    const spawnOptions: SpawnOptions = {
      cwd: options.cwd,
      env: options.env ? { ...process.env, ...options.env } : process.env,
      shell: false, // Strict: never use shell to prevent command injection
      stdio: ['pipe', 'pipe', 'pipe']
    };

    let proc: ReturnType<typeof spawn>;
    try {
      proc = spawn(executable, args, spawnOptions);
    } catch (err: any) {
      resolve({
        stdout: '',
        stderr: err?.message || String(err),
        exitCode: -1,
        durationMs: Date.now() - startTime,
        timedOut: false,
        error: err
      });
      return;
    }

    if (options.abortSignal) {
      options.abortSignal.addEventListener('abort', () => {
        try {
          proc.kill('SIGKILL');
        } catch {}
      });
    }

    timer = setTimeout(() => {
      timedOut = true;
      try {
        proc.kill('SIGKILL');
      } catch {}
    }, timeoutMs);

    proc.stdout?.on('data', (chunk: Buffer) => {
      if (stdout.length + chunk.length <= maxBuffer) {
        stdout += chunk.toString('utf8');
      }
    });

    proc.stderr?.on('data', (chunk: Buffer) => {
      if (stderr.length + chunk.length <= maxBuffer) {
        stderr += chunk.toString('utf8');
      }
    });

    proc.on('error', (err) => {
      if (timer) clearTimeout(timer);
      resolve({
        stdout,
        stderr: stderr || err.message,
        exitCode: -1,
        durationMs: Date.now() - startTime,
        timedOut,
        error: err
      });
    });

    proc.on('close', (code) => {
      if (timer) clearTimeout(timer);
      resolve({
        stdout,
        stderr,
        exitCode: code,
        durationMs: Date.now() - startTime,
        timedOut
      });
    });
  });
}
