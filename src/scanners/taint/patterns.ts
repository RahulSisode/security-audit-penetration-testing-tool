export interface TaintPattern {
  name: string;
  type: 'SOURCE' | 'SANITIZER' | 'SINK';
  category?: 'SQLI' | 'CMDI' | 'XSS' | 'PATH' | 'SSRF' | 'DESERIALIZATION' | 'REDIRECT';
  patterns: RegExp[];
  description: string;
}

export const TAINT_SOURCES: TaintPattern[] = [
  {
    name: 'Express / Node.js HTTP Request Parameter',
    type: 'SOURCE',
    patterns: [
      /req\.(?:query|body|params|headers|cookies)(?:\.[a-zA-Z0-9_]+|\[['"][^'"]+['"]\])?/g,
      /request\.(?:query|body|params|headers|cookies)(?:\.[a-zA-Z0-9_]+|\[['"][^'"]+['"]\])?/g
    ],
    description: 'Untrusted user input from HTTP request'
  },
  {
    name: 'FastAPI / Flask / Django Request Parameter',
    type: 'SOURCE',
    patterns: [
      /request\.(?:args|form|values|data|json|GET|POST)(?:\[['"][^'"]+['"]\]|\.get\(['"][^'"]+['"]\))/g,
      /sys\.argv\[\d+\]/g,
      /input\s*\([^)]*\)/g
    ],
    description: 'Untrusted input from Python request/CLI'
  },
  {
    name: 'DOM Location / URL Parameters',
    type: 'SOURCE',
    patterns: [
      /location\.(?:search|hash|pathname|href)/g,
      /window\.location\.(?:search|hash|pathname|href)/g,
      /new\s+URLSearchParams\s*\([^)]*\)/g,
      /document\.URL|document\.documentURI/g
    ],
    description: 'Untrusted input from client-side URL/DOM'
  }
];

export const TAINT_SANITIZERS: TaintPattern[] = [
  {
    name: 'HTML Sanitizer',
    type: 'SANITIZER',
    category: 'XSS',
    patterns: [
      /DOMPurify\.sanitize\s*\(/g,
      /escapeHtml\s*\(/g,
      /sanitizeHtml\s*\(/g,
      /encodeURIComponent\s*\(/g
    ],
    description: 'HTML sanitization or encoding'
  },
  {
    name: 'Path Sanitizer',
    type: 'SANITIZER',
    category: 'PATH',
    patterns: [
      /path\.basename\s*\(/g,
      /path\.resolve\s*\(/g,
      /isPathInside\s*\(/g,
      /replace\s*\(\s*\/(\.\.|\/|\\\\)\/g/g
    ],
    description: 'Path normalization and boundary verification'
  },
  {
    name: 'Integer / Numeric Cast',
    type: 'SANITIZER',
    patterns: [
      /parseInt\s*\(/g,
      /Number\s*\(/g,
      /int\s*\(/g,
      /float\s*\(/g
    ],
    description: 'Numeric type casting'
  },
  {
    name: 'Shell Quote / Escape',
    type: 'SANITIZER',
    category: 'CMDI',
    patterns: [
      /shlex\.quote\s*\(/g,
      /escapeshellarg\s*\(/g,
      /escapeshellcmd\s*\(/g
    ],
    description: 'Shell argument escaping'
  }
];

export const TAINT_SINKS: TaintPattern[] = [
  {
    name: 'SQL Query Execution Sink',
    type: 'SINK',
    category: 'SQLI',
    patterns: [
      /(?:db|conn|cursor|client|pool)\.(?:query|execute|raw)\s*\(\s*([a-zA-Z0-9_\$]+)/g,
      /\$conn->query\s*\(\s*\$([a-zA-Z0-9_]+)/g
    ],
    description: 'Direct SQL execution sink'
  },
  {
    name: 'Command Execution Sink',
    type: 'SINK',
    category: 'CMDI',
    patterns: [
      /(?:child_process|cp)\.(?:exec|execSync)\s*\(\s*([a-zA-Z0-9_\$]+)/g,
      /os\.system\s*\(\s*([a-zA-Z0-9_]+)/g,
      /subprocess\.(?:call|Popen|run)\s*\(\s*([a-zA-Z0-9_]+)/g
    ],
    description: 'OS command execution sink'
  },
  {
    name: 'File System Access Sink',
    type: 'SINK',
    category: 'PATH',
    patterns: [
      /fs\.(?:readFile|readFileSync|writeFile|writeFileSync|unlink|createReadStream)\s*\(\s*([a-zA-Z0-9_\$]+)/g,
      /open\s*\(\s*([a-zA-Z0-9_]+)/g
    ],
    description: 'File system access sink'
  },
  {
    name: 'SSRF HTTP Request Sink',
    type: 'SINK',
    category: 'SSRF',
    patterns: [
      /(?:axios|fetch|requests\.(?:get|post|request)|http\.get)\s*\(\s*([a-zA-Z0-9_\$]+)/g
    ],
    description: 'Network request destination sink'
  },
  {
    name: 'DOM XSS Sink',
    type: 'SINK',
    category: 'XSS',
    patterns: [
      /document\.getElementById\([^)]+\)\.innerHTML\s*=\s*([a-zA-Z0-9_\$]+)/g,
      /([a-zA-Z0-9_\$]+)\.innerHTML\s*=\s*([a-zA-Z0-9_\$]+)/g,
      /document\.write\s*\(\s*([a-zA-Z0-9_\$]+)\s*\)/g
    ],
    description: 'DOM HTML sink'
  }
];
