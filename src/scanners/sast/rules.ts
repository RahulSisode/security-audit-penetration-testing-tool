import { VulnerabilityCategory, Severity, Confidence } from '../../core/types';

export interface SASTRule {
  id: string;
  name: string;
  category: VulnerabilityCategory;
  severity: Severity;
  confidence: Confidence;
  languages: string[];
  description: string;
  patterns: RegExp[];
  antiPatterns?: RegExp[]; // If present, suppresses false positive
  cwe: string[];
  owasp: string[];
  cvss: number;
  exploitPreconditions: string;
  impact: string;
  remediation: string;
  generateFix?: (code: string, match: RegExpExecArray) => { replacement: string; explanation: string };
}

export const SAST_RULES: SASTRule[] = [
  // 1. SQL Injection
  {
    id: 'SENTINEL-SAST-SQLI-001',
    name: 'Unparameterized SQL Query Construction',
    category: 'INJECTION',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    languages: ['JavaScript', 'TypeScript', 'Python', 'Java', 'PHP', 'Go', 'C#', 'Ruby'],
    description: 'Dynamic SQL query built with direct string concatenation or formatting allows SQL Injection.',
    patterns: [
      /(?:db|database|connection|client|conn|cursor|pool)\.(?:query|execute|raw|all|get)\s*\(\s*(?:[`'"]SELECT|[`'"]INSERT|[`'"]UPDATE|[`'"]DELETE|[`'"]DROP)[\s\S]*?\$\{[^}]+\}/i,
      /(?:db|database|connection|client|conn|cursor|pool)\.(?:query|execute|raw)\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE|DROP)[\s\S]*?["']\s*\+\s*[a-zA-Z0-9_\.]+/i,
      /(?:const|let|var)\s+[a-zA-Z0-9_\$]+\s*=\s*["'](?:SELECT|INSERT|UPDATE|DELETE|DROP)[\s\S]*?["']\s*\+\s*[a-zA-Z0-9_\.]+/i,
      /(?:const|let|var)\s+[a-zA-Z0-9_\$]+\s*=\s*[`'"](?:SELECT|INSERT|UPDATE|DELETE|DROP)[\s\S]*?\$\{[^}]+\}/i,
      /cursor\.execute\s*\(\s*f["'](?:SELECT|INSERT|UPDATE|DELETE)[\s\S]*?\{[^}]+\}/i,
      /cursor\.execute\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE)[\s\S]*?%s?["']\s*%\s*[a-zA-Z0-9_]+/i,
      /\$conn->query\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE)[\s\S]*?["']\s*\.\s*\$[a-zA-Z0-9_]+/i
    ],
    antiPatterns: [
      /\$1|\$2|\?|:[a-zA-Z0-9_]+/, // Parameter placeholders
      /prepare\s*\(/
    ],
    cwe: ['CWE-89'],
    owasp: ['A03:2021-Injection'],
    cvss: 9.8,
    exploitPreconditions: 'Untrusted input reachable in SQL query concatenation.',
    impact: 'Full database read, modification, or potential Remote Code Execution via stacked queries or xp_cmdshell.',
    remediation: 'Use parameterized queries or prepared statements (e.g., db.query("SELECT * FROM users WHERE id = $1", [userId])).',
    generateFix: (code, match) => ({
      replacement: code.replace(/(\.query\s*\(\s*)([`'"].*?)(?:\$\{|\+\s*)([a-zA-Z0-9_\.]+)(?:\}|)(.*?)([`'"]\s*\))/i, '$1$2$1_PARAM$4, [$3])'),
      explanation: 'Converted string concatenation to parameterized query placeholder with bound parameter array.'
    })
  },

  // 2. OS Command Injection
  {
    id: 'SENTINEL-SAST-CMDI-001',
    name: 'Unsanitized OS Command Execution',
    category: 'INJECTION',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    languages: ['JavaScript', 'TypeScript', 'Python', 'Java', 'PHP', 'Go', 'Ruby'],
    description: 'Direct execution of system commands with concatenated arguments permits shell command injection.',
    patterns: [
      /(?:child_process|cp)\.(?:exec|execSync)\s*\(\s*(?:[`'"].*?\$\{|["'].*?["']\s*\+)/i,
      /os\.system\s*\(\s*(?:f["']|["'].*?["']\s*\+|\%)/i,
      /subprocess\.(?:call|Popen|run)\s*\(\s*(?:f["']|["'].*?["']\s*\+).*?shell\s*=\s*True/i,
      /shell_exec\s*\(\s*.*?\$[a-zA-Z0-9_]+/i,
      /exec\s*\(\s*.*?\$[a-zA-Z0-9_]+/i,
      /Runtime\.getRuntime\(\)\.exec\s*\(\s*.*?["']\s*\+/i
    ],
    antiPatterns: [
      /execFile|spawn\s*\([^,]+,\s*\[/,
      /shlex\.quote/
    ],
    cwe: ['CWE-78'],
    owasp: ['A03:2021-Injection'],
    cvss: 9.8,
    exploitPreconditions: 'Attacker controls command string or argument values.',
    impact: 'Arbitrary shell command execution with privileges of the running application process.',
    remediation: 'Use execFile or spawn with argument arrays without shell: true, or sanitize arguments with shlex.quote / escapeshellarg.'
  },

  // 3. Cross-Site Scripting (XSS) & Unsafe HTML Rendering
  {
    id: 'SENTINEL-SAST-XSS-001',
    name: 'Unsafe HTML / DOM Injection (XSS)',
    category: 'XSS',
    severity: 'HIGH',
    confidence: 'HIGH',
    languages: ['JavaScript', 'TypeScript', 'HTML'],
    description: 'Writing unescaped data to innerHTML, outerHTML, or dangerouslySetInnerHTML leads to Cross-Site Scripting.',
    patterns: [
      /\.innerHTML\s*=\s*[^;\n]+/i,
      /\.outerHTML\s*=\s*[^;\n]+/i,
      /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?!DOMPurify)[^}]+/i,
      /document\.write\s*\([^)]+\)/i,
      /v-html\s*=\s*["'][^"']+["']/i
    ],
    antiPatterns: [
      /DOMPurify\.sanitize/,
      /escapeHtml/,
      /sanitizeHtml/
    ],
    cwe: ['CWE-79'],
    owasp: ['A03:2021-Injection'],
    cvss: 7.2,
    exploitPreconditions: 'Untrusted user input reflected into DOM sink.',
    impact: 'Session hijacking, credential theft, DOM defacement, unauthorized client-side actions.',
    remediation: 'Use textContent / innerText instead of innerHTML, or sanitize with DOMPurify.sanitize().',
    generateFix: (code, match) => ({
      replacement: code.replace(/\.innerHTML\s*=/g, '.textContent ='),
      explanation: 'Replaced .innerHTML with safe .textContent to prevent HTML and script interpretation.'
    })
  },

  // 4. Path Traversal
  {
    id: 'SENTINEL-SAST-PATH-001',
    name: 'Path Traversal / Arbitrary File Access',
    category: 'PATH_TRAVERSAL',
    severity: 'HIGH',
    confidence: 'HIGH',
    languages: ['JavaScript', 'TypeScript', 'Python', 'Java', 'Go', 'PHP'],
    description: 'File system access using unvalidated path concatenation allows directory traversal (../).',
    patterns: [
      /fs\.(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink|unlinkSync)\s*\(\s*(?:path\.join\([^)]*req\.|[`'"].*?\$\{(?:req|param|query|input)|["'].*?["']\s*\+\s*(?:req|param|query|filename|file))/i,
      /open\s*\(\s*(?:os\.path\.join\([^)]*(?:request|filename|user_input)|f["'].*?\{(?:request|filename|user_input)\})/i,
      /new\s+File\s*\(\s*(?:request|params|userDir)[\s\S]*?\)/i
    ],
    antiPatterns: [
      /path\.resolve|normalize|isPathInside|startsWith\(baseDir\)/
    ],
    cwe: ['CWE-22', 'CWE-73'],
    owasp: ['A01:2021-Broken Access Control'],
    cvss: 7.5,
    exploitPreconditions: 'Attacker supplies ../ sequence in file parameter.',
    impact: 'Unauthorized reading or overwriting of sensitive system files, keys, and configurations.',
    remediation: 'Validate resolved path with path.resolve() and ensure it starts with authorized base directory.'
  },

  // 5. Server-Side Request Forgery (SSRF)
  {
    id: 'SENTINEL-SAST-SSRF-001',
    name: 'Server-Side Request Forgery (SSRF)',
    category: 'SSRF',
    severity: 'HIGH',
    confidence: 'HIGH',
    languages: ['JavaScript', 'TypeScript', 'Python', 'Go', 'Java', 'PHP'],
    description: 'HTTP request dispatched to a user-supplied URL without strict scheme/host whitelist validation.',
    patterns: [
      /(?:axios|fetch|http\.get|https\.get|urllib\.request\.urlopen|requests\.get|requests\.post)\s*\(\s*(?:req\.(?:query|body|params)|request\.(?:args|form|data|GET|POST)|\$[a-zA-Z0-9_]+->getParam)/i,
      /(?:axios|fetch|requests\.(?:get|post|request)|http\.get)\s*\(\s*(?:url|targetUrl|userUrl|target|dest|endpoint|reqUrl)\s*[,)]/i
    ],
    antiPatterns: [
      /whitelist|ALLOWED_HOSTS|parseUrl|isValidHost/i
    ],
    cwe: ['CWE-918'],
    owasp: ['A10:2021-Server-Side Request Forgery'],
    cvss: 8.6,
    exploitPreconditions: 'Untrusted URL accepted and fetched server-side.',
    impact: 'Access to cloud metadata services (169.254.169.254), internal VPC services, and port scanning.',
    remediation: 'Enforce strict domain whitelist, validate protocols (only http/https), and block private IP ranges (RFC 1918, link-local metadata).'
  },

  // 6. Insecure Deserialization
  {
    id: 'SENTINEL-SAST-DESER-001',
    name: 'Insecure Object Deserialization',
    category: 'DESERIALIZATION',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    languages: ['JavaScript', 'TypeScript', 'Python', 'Java', 'PHP', 'Ruby'],
    description: 'Deserializing untrusted data with native deserializers allows arbitrary object instantiation and RCE.',
    patterns: [
      /(?:serialize|nodeSerialize|node-serialize|serialize-javascript)\.unserialize\s*\(/i,
      /\.unserialize\s*\(/i,
      /pickle\.(?:loads|load)\s*\(/i,
      /_pickle\.(?:loads|load)\s*\(/i,
      /yaml\.(?:load|unsafe_load)\s*\([^,)]*(?!\s*,\s*Loader\s*=\s*(?:yaml\.)?SafeLoader)/i,
      /unserialize\s*\(\s*\$[a-zA-Z0-9_]+/i,
      /new\s+ObjectInputStream\s*\(/i,
      /Marshal\.load\s*\(/i
    ],
    antiPatterns: [
      /yaml\.safe_load|yaml\.SafeLoader|JSON\.parse/
    ],
    cwe: ['CWE-502'],
    owasp: ['A08:2021-Software and Data Integrity Failures'],
    cvss: 9.8,
    exploitPreconditions: 'Untrusted serialized payload parsed by application.',
    impact: 'Remote Code Execution, privilege escalation, or application state corruption.',
    remediation: 'Use safe formats such as JSON (JSON.parse), yaml.safe_load, or protobuf instead of native object deserializers.'
  },

  // 7. XML External Entity (XXE)
  {
    id: 'SENTINEL-SAST-XXE-001',
    name: 'XML External Entity Processing (XXE)',
    category: 'XXE',
    severity: 'HIGH',
    confidence: 'HIGH',
    languages: ['Java', 'Python', 'PHP', 'JavaScript', 'C#'],
    description: 'XML parser configured with external entity expansion enabled.',
    patterns: [
      /xml\.etree\.ElementTree\.parse\s*\(/i,
      /DocumentBuilderFactory\.newInstance\s*\(\)/i,
      /SAXParserFactory\.newInstance\s*\(\)/i,
      /libxml_disable_entity_loader\s*\(\s*false\s*\)/i,
      /XMLReaderFactory\.createXMLReader\s*\(\)/i
    ],
    antiPatterns: [
      /setFeature\s*\(\s*["']http:\/\/apache.org\/xml\/features\/disallow-doctype-decl["']\s*,\s*true\s*\)/,
      /defusedxml/
    ],
    cwe: ['CWE-611'],
    owasp: ['A05:2021-Security Misconfiguration'],
    cvss: 8.2,
    exploitPreconditions: 'XML parser processes XML documents containing DOCTYPE entity definitions.',
    impact: 'Server file disclosure, SSRF, or local denial of service (Billion Laughs attack).',
    remediation: 'Disable DTDs (disallow-doctype-decl: true) or use defusedxml in Python.'
  },

  // 8. Cryptographic Weakness - Weak Hashing or Ciphers
  {
    id: 'SENTINEL-SAST-CRYPTO-001',
    name: 'Insecure Cryptographic Algorithm (MD5 / SHA-1 / DES / RC4 / ECB)',
    category: 'CRYPTOGRAPHY',
    severity: 'MEDIUM',
    confidence: 'HIGH',
    languages: ['JavaScript', 'TypeScript', 'Python', 'Java', 'Go', 'C#', 'C', 'C++'],
    description: 'Use of broken or deprecated cryptographic algorithms (MD5, SHA1, DES, 3DES, RC4, or ECB cipher mode).',
    patterns: [
      /crypto\.createHash\s*\(\s*["'](?:md5|sha1)["']\s*\)/i,
      /hashlib\.(?:md5|sha1)\s*\(/i,
      /MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-1|SHA1|DES)["']\s*\)/i,
      /crypto\.createCipheriv?\s*\(\s*["'][^"']*-ecb["']/i,
      /Cipher\.getInstance\s*\(\s*["'][^"']+\/ECB\//i
    ],
    cwe: ['CWE-327', 'CWE-328'],
    owasp: ['A02:2021-Cryptographic Failures'],
    cvss: 5.9,
    exploitPreconditions: 'Weak hash or cipher used for security-critical validation or encryption.',
    impact: 'Hash collision attacks, plaintext recovery from predictable cipher blocks.',
    remediation: 'Use SHA-256/SHA-512 for integrity, bcrypt/Argon2id for passwords, and AES-GCM for symmetric encryption.'
  },

  // 9. Insecure Random Number Generation
  {
    id: 'SENTINEL-SAST-RNG-001',
    name: 'Predictable Pseudo-Random Number Generator',
    category: 'INSECURE_RNG',
    severity: 'MEDIUM',
    confidence: 'HIGH',
    languages: ['JavaScript', 'TypeScript', 'Python', 'Java', 'Go', 'PHP', 'C', 'C++'],
    description: 'Using Math.random(), random.random(), or rand() for security tokens, passwords, or session IDs.',
    patterns: [
      /(?:token|secret|session|nonce|key|password|auth|code)\s*[:=][^;\n]*Math\.random\s*\(\)/i,
      /(?:token|secret|session|nonce|key|password|auth|code)\s*=[^;\n]*random\.(?:random|choice|randint)\s*\(/i,
      /(?:token|secret|session|nonce|key|password|auth)\s*=[^;\n]*(?:rand|mt_rand)\s*\(/i
    ],
    antiPatterns: [
      /crypto\.randomBytes|crypto\.getRandomValues|secrets\.token_hex|SecureRandom/
    ],
    cwe: ['CWE-330', 'CWE-338'],
    owasp: ['A02:2021-Cryptographic Failures'],
    cvss: 6.5,
    exploitPreconditions: 'Attacker observes seed or PRNG sequence to predict security tokens.',
    impact: 'Token prediction, session hijacking, password reset takeover.',
    remediation: 'Use crypto.randomBytes() / window.crypto.getRandomValues() in JS, secrets module in Python, or SecureRandom in Java.'
  },

  // 10. Prototype Pollution
  {
    id: 'SENTINEL-SAST-PROTO-001',
    name: 'Prototype Pollution via Unsafe Property Assignment',
    category: 'PROTOTYPE_POLLUTION',
    severity: 'HIGH',
    confidence: 'HIGH',
    languages: ['JavaScript', 'TypeScript'],
    description: 'Recursive object merge or direct assignment to __proto__ / constructor.prototype modifies Object prototype.',
    patterns: [
      /\[(?:key|prop|target)\]\s*=\s*(?:value|src\[key\])/i,
      /target\[['"]__proto__['"]\]/i,
      /Object\.assign\s*\(\s*(?:\{\}|target),\s*(?:JSON\.parse|req\.body)/i
    ],
    antiPatterns: [
      /hasOwnProperty|Object\.create\(null\)|key\s*!==\s*['"]__proto__['"]/
    ],
    cwe: ['CWE-1321'],
    owasp: ['A03:2021-Injection'],
    cvss: 7.5,
    exploitPreconditions: 'User-controlled JSON payload with __proto__ merged into application objects.',
    impact: 'Denial of service, property injection, bypass of security checks, or potential gadget RCE.',
    remediation: 'Validate keys against __proto__, constructor, and prototype, or use Object.create(null).'
  },

  // 11. Dynamic Code Execution (eval / Function)
  {
    id: 'SENTINEL-SAST-EVAL-001',
    name: 'Unsafe Dynamic Code Execution (eval / Function constructor)',
    category: 'UNSAFE_REFLECTION',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    languages: ['JavaScript', 'TypeScript', 'Python', 'PHP', 'Ruby'],
    description: 'Passing untrusted strings to eval(), Function(), or exec() leads to immediate code execution.',
    patterns: [
      /\beval\s*\(\s*(?![0-9\s"']+\s*\))[^)]+\)/i,
      /new\s+Function\s*\([^)]*(?:req|query|input|data|param)[^)]*\)/i,
      /setTimeout\s*\(\s*["'`][^"'`]*\$\{[^}]+\}/i
    ],
    cwe: ['CWE-95'],
    owasp: ['A03:2021-Injection'],
    cvss: 9.8,
    exploitPreconditions: 'Dynamic code execution contains user-controlled string.',
    impact: 'Arbitrary code execution on client or server.',
    remediation: 'Avoid eval() and new Function(). Parse structured data with JSON.parse() or use safe lookup maps.'
  },

  // 12. Regular Expression Denial of Service (ReDoS)
  {
    id: 'SENTINEL-SAST-REDOS-001',
    name: 'Catastrophic Backtracking Regular Expression (ReDoS)',
    category: 'REDOS',
    severity: 'MEDIUM',
    confidence: 'HIGH',
    languages: ['JavaScript', 'TypeScript', 'Python', 'Java', 'PHP', 'Go', 'Ruby'],
    description: 'Nested quantifiers in regular expressions ((a+)+ or (.*a)+) cause exponential backtracking and DoS.',
    patterns: [
      /\/(?:[a-zA-Z0-9_\-\.]+\+)+\+\//,
      /RegExp\s*\(\s*["'].*?\([^)]+\+[\s\S]*?\+.*["']\s*\)/i,
      /re\.compile\s*\(\s*r?["'].*?\([^)]+\+[\s\S]*?\+.*["']\s*\)/i
    ],
    cwe: ['CWE-1333'],
    owasp: ['A04:2021-Insecure Design'],
    cvss: 6.5,
    exploitPreconditions: 'Attacker sends long crafted input matching prefix but failing match.',
    impact: 'CPU exhaustion, thread starvation, complete denial of service.',
    remediation: 'Refactor regex to eliminate nested ambiguous quantifiers or use linear-time regex engines (e.g. RE2).'
  },

  // 13. Sensitive Data Exposure / Insecure Logging
  {
    id: 'SENTINEL-SAST-LOGGING-001',
    name: 'Sensitive Credential / PII Logging',
    category: 'SENSITIVE_DATA_EXPOSURE',
    severity: 'HIGH',
    confidence: 'HIGH',
    languages: ['JavaScript', 'TypeScript', 'Python', 'Java', 'Go', 'C#', 'PHP', 'Ruby'],
    description: 'Logging passwords, tokens, API keys, credit cards, or authorization headers to console/log files.',
    patterns: [
      /(?:console\.log|console\.info|console\.error|logger\.(?:info|debug|error|warn)|logging\.(?:info|debug|error))\s*\([^)]*(?:password|passwd|apiKey|token|secret|credit_card|cvv|authorization|ssn)/i,
      /System\.out\.println\s*\([^)]*(?:password|passwd|apiKey|token|secret)/i
    ],
    antiPatterns: [
      /mask|redact|hash|sanitize/i
    ],
    cwe: ['CWE-532'],
    owasp: ['A09:2021-Security Logging and Monitoring Failures'],
    cvss: 6.5,
    exploitPreconditions: 'Log files readable by developers, monitoring systems, or storage backups.',
    impact: 'Credential leakage, regulatory compliance violations (GDPR, PCI-DSS).',
    remediation: 'Redact or mask sensitive parameters before passing to logging functions.'
  },

  // 14. Unsafe Open Redirect
  {
    id: 'SENTINEL-SAST-REDIRECT-001',
    name: 'Unvalidated URL Open Redirect',
    category: 'UNSAFE_REDIRECT',
    severity: 'MEDIUM',
    confidence: 'HIGH',
    languages: ['JavaScript', 'TypeScript', 'Python', 'Java', 'PHP', 'C#'],
    description: 'Redirecting users to unvalidated destination URLs allows phishing and credential harvesting.',
    patterns: [
      /res\.redirect\s*\(\s*(?:req\.(?:query|params|body)|url|targetUrl|redirectUrl)\s*\)/i,
      /redirect\s*\(\s*request\.(?:args|GET|form)\[['"](?:next|url|redirect|return)['"]\]/i,
      /header\s*\(\s*["']Location:\s*["']\s*\.\s*\$[a-zA-Z0-9_]+/i
    ],
    antiPatterns: [
      /startsWith\(["']\/["']\)|isSafeRedirect|ALLOWED_HOSTS/i
    ],
    cwe: ['CWE-601'],
    owasp: ['A01:2021-Broken Access Control'],
    cvss: 6.1,
    exploitPreconditions: 'User clicks link with attacker-crafted redirect target parameter.',
    impact: 'User redirected to spoofed phishing domain after authentication.',
    remediation: 'Ensure redirect destination is a relative path starting with / or validate against a strict allowed domain list.'
  },

  // 15. Insecure Temporary File Creation
  {
    id: 'SENTINEL-SAST-TEMPFILE-001',
    name: 'Predictable Insecure Temporary File Creation',
    category: 'INSECURE_TEMP_FILE',
    severity: 'MEDIUM',
    confidence: 'HIGH',
    languages: ['Python', 'C', 'C++', 'Java', 'PHP', 'Shell'],
    description: 'Using tempfile.mktemp(), tmpnam(), or hardcoded /tmp paths creates symlink and race condition vulnerabilities.',
    patterns: [
      /tempfile\.mktemp\s*\(/i,
      /\btmpnam\s*\(/i,
      /\btempnam\s*\(/i,
      /open\s*\(\s*["']\/tmp\/[^"']+["']/i,
      /fs\.writeFile(?:Sync)?\s*\(\s*["']\/tmp\/[^"']+["']/i
    ],
    antiPatterns: [
      /tempfile\.NamedTemporaryFile|mkstemp/
    ],
    cwe: ['CWE-377', 'CWE-378'],
    owasp: ['A05:2021-Security Misconfiguration'],
    cvss: 5.5,
    exploitPreconditions: 'Local attacker pre-creates symlink in shared /tmp directory.',
    impact: 'Arbitrary file overwrite or unauthorized file reading.',
    remediation: 'Use secure atomic temporary file utilities such as tempfile.NamedTemporaryFile() or mkstemp().'
  },

  // 16. Memory Safety - C/C++ Buffer Overflow & Unsafe Functions
  {
    id: 'SENTINEL-SAST-MEM-001',
    name: 'Unsafe C/C++ Memory Function (strcpy / gets / sprintf / strcat)',
    category: 'MEMORY_SAFETY',
    severity: 'HIGH',
    confidence: 'HIGH',
    languages: ['C', 'C++', 'C/C++ Header', 'C++ Header'],
    description: 'Unbounded buffer copy functions cause stack and heap buffer overflows.',
    patterns: [
      /\bgets\s*\(/i,
      /\bstrcpy\s*\(\s*[a-zA-Z0-9_\->\.]+\s*,\s*[a-zA-Z0-9_\->\.]+\s*\)/i,
      /\bsprintf\s*\(\s*[a-zA-Z0-9_\->\.]+\s*,\s*["'][^"']*%s[^"']*["']/i,
      /\bstrcat\s*\(\s*[a-zA-Z0-9_\->\.]+\s*,\s*[a-zA-Z0-9_\->\.]+\s*\)/i
    ],
    antiPatterns: [
      /strncpy|snprintf|strlcpy/
    ],
    cwe: ['CWE-120', 'CWE-676'],
    owasp: ['A04:2021-Insecure Design'],
    cvss: 8.8,
    exploitPreconditions: 'Input exceeds destination buffer size.',
    impact: 'Stack corruption, control-flow hijack, arbitrary code execution.',
    remediation: 'Use bounded functions such as strncpy, snprintf, or C++ std::string.'
  },

  // 17. Memory Safety - Format String Vulnerability
  {
    id: 'SENTINEL-SAST-FMT-001',
    name: 'Uncontrolled Format String Vulnerability',
    category: 'FORMAT_STRING',
    severity: 'HIGH',
    confidence: 'HIGH',
    languages: ['C', 'C++', 'C/C++ Header', 'C++ Header'],
    description: 'Passing variable directly as format string parameter to printf, syslog, or sprintf.',
    patterns: [
      /\bprintf\s*\(\s*[a-zA-Z0-9_\->\.]+\s*\)/i,
      /\bfprintf\s*\(\s*[a-zA-Z0-9_\->\.]+\s*,\s*[a-zA-Z0-9_\->\.]+\s*\)/i,
      /\bsyslog\s*\(\s*[A-Z_]+\s*,\s*[a-zA-Z0-9_\->\.]+\s*\)/i
    ],
    antiPatterns: [
      /printf\s*\(\s*["']/
    ],
    cwe: ['CWE-134'],
    owasp: ['A03:2021-Injection'],
    cvss: 8.6,
    exploitPreconditions: 'Attacker supplies format specifiers (%x, %n) in string parameter.',
    impact: 'Arbitrary memory read, stack disclosure, memory write (%n) leading to RCE.',
    remediation: 'Always supply a constant format string, e.g. printf("%s", userString);'
  },

  // 18. Broken Authentication & Missing CSRF on State-Changing Routes
  {
    id: 'SENTINEL-SAST-AUTH-001',
    name: 'Disabled Authentication or CSRF Protection',
    category: 'AUTH_AUTHZ',
    severity: 'HIGH',
    confidence: 'HIGH',
    languages: ['JavaScript', 'TypeScript', 'Python', 'Java', 'PHP', 'C#'],
    description: 'Explicitly disabling authentication checks, security filters, or CSRF validation.',
    patterns: [
      /csrf\s*:\s*false/i,
      /\.csrf\(\)\.disable\(\)/i,
      /verify\s*=\s*False/i,
      /rejectUnauthorized\s*:\s*false/i,
      /passport\.authenticate\s*\([^)]*\)\s*,\s*\(req,\s*res\)\s*=>/i
    ],
    cwe: ['CWE-352', 'CWE-287', 'CWE-295'],
    owasp: ['A07:2021-Identification and Authentication Failures'],
    cvss: 7.5,
    exploitPreconditions: 'CSRF or certificate validation disabled in production environment.',
    impact: 'Cross-Site Request Forgery, man-in-the-middle attacks, unauthorized API access.',
    remediation: 'Enable CSRF tokens for state-changing requests and maintain strict TLS certificate verification.'
  },

  // 19. Broken Access Control / IDOR Pattern
  {
    id: 'SENTINEL-SAST-IDOR-001',
    name: 'Direct Object Reference Without Owner Verification',
    category: 'IDOR_BOLA',
    severity: 'HIGH',
    confidence: 'MEDIUM',
    languages: ['JavaScript', 'TypeScript', 'Python', 'Java', 'PHP', 'Go'],
    description: 'Querying or modifying user records directly by user-supplied ID without verifying ownership/tenant.',
    patterns: [
      /(?:User|Account|Profile|Order|Document)\.findByPk\s*\(\s*req\.params\.id\s*\)/i,
      /(?:User|Account|Profile|Order|Document)\.findById\s*\(\s*req\.params\.id\s*\)/i,
      /SELECT\s+\*\s+FROM\s+(?:users|accounts|profiles|documents)\s+WHERE\s+id\s*=\s*['"]?\s*\+\s*req\.params\.id/i
    ],
    antiPatterns: [
      /req\.user\.id|session\.userId|auth\.userId|where:\s*\{[^}]*userId/i
    ],
    cwe: ['CWE-639', 'CWE-284'],
    owasp: ['A01:2021-Broken Access Control'],
    cvss: 7.5,
    exploitPreconditions: 'Attacker modifies resource ID in URL parameter.',
    impact: 'Unauthorized access, reading, or modification of other users private data.',
    remediation: 'Scope queries to the authenticated user ID (e.g., findOne({ id: req.params.id, userId: req.user.id })).'
  },

  // 20. Insecure File Upload
  {
    id: 'SENTINEL-SAST-UPLOAD-001',
    name: 'Unrestricted File Upload Without Type or Extension Validation',
    category: 'FILE_UPLOAD',
    severity: 'HIGH',
    confidence: 'HIGH',
    languages: ['JavaScript', 'TypeScript', 'Python', 'PHP', 'Java'],
    description: 'Saving uploaded file directly using original user-supplied filename.',
    patterns: [
      /cb\s*\(\s*null\s*,\s*file\.originalname\s*\)/i,
      /destination:\s*["'][^"']+["'],\s*filename:\s*\(req,\s*file,\s*cb\)\s*=>/i,
      /move_uploaded_file\s*\(\s*\$_FILES\[[^\]]+\]\['tmp_name'\]\s*,\s*["'][^"']+["']\s*\.\s*\$_FILES\[[^\]]+\]\['name'\]/i
    ],
    antiPatterns: [
      /uuid|crypto\.randomUUID|extname\.toLowerCase\(\)\s*===/
    ],
    cwe: ['CWE-434'],
    owasp: ['A04:2021-Insecure Design'],
    cvss: 8.5,
    exploitPreconditions: 'Attacker uploads executable payload (.php, .jsp, .sh, .html) preserving filename.',
    impact: 'Remote Code Execution or Stored XSS via uploaded files.',
    remediation: 'Generate a random UUID filename server-side and validate MIME types and file extensions against a strict whitelist.'
  }
];
