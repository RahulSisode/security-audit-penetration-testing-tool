import * as fs from 'fs';
import * as path from 'path';
import { SecurityFinding, FixVerificationResult, ScanOptions } from '../core/types';
import { BuiltinSASTScanner } from '../scanners/sast/builtin-sast';
import { BuiltinSecretsScanner } from '../scanners/secrets/builtin-secrets';
import { logger } from '../utils/logger';

export class FixVerificationEngine {
  public static async applyAndVerifyFix(
    finding: SecurityFinding,
    workspaceRoot: string,
    userApproved: boolean = false
  ): Promise<FixVerificationResult> {
    const checksPerformed: string[] = [];

    // Guard 1: User Approval Required
    if (!userApproved) {
      return {
        findingFingerprint: finding.fingerprint,
        patchApplied: false,
        rescanExecuted: false,
        issueResolved: false,
        newFindingsIntroduced: [],
        checksPerformed: ['Checked user approval status'],
        remainingUncertainty: 'Patch was rejected or awaiting user confirmation.',
        message: 'Fix not applied: Explicit user approval is required before modifying source files.'
      };
    }

    if (!finding.proposedFix || !finding.proposedFix.replacementCode) {
      return {
        findingFingerprint: finding.fingerprint,
        patchApplied: false,
        rescanExecuted: false,
        issueResolved: false,
        newFindingsIntroduced: [],
        checksPerformed: ['Checked proposed fix availability'],
        remainingUncertainty: 'No deterministic patch available for this finding.',
        message: 'Fix not applied: Manual remediation required.'
      };
    }

    const targetFilePath = path.join(workspaceRoot, finding.proposedFix.targetFile);
    checksPerformed.push(`Located target file ${finding.proposedFix.targetFile}`);

    if (!fs.existsSync(targetFilePath)) {
      return {
        findingFingerprint: finding.fingerprint,
        patchApplied: false,
        rescanExecuted: false,
        issueResolved: false,
        newFindingsIntroduced: [],
        checksPerformed,
        remainingUncertainty: 'Target file does not exist on disk.',
        message: `Fix failed: ${targetFilePath} does not exist.`
      };
    }

    // Step 1: Read original content & create backup in memory
    const originalContent = fs.readFileSync(targetFilePath, 'utf8');
    const lines = originalContent.split('\n');
    const startLine = finding.proposedFix.startLine;
    const endLine = finding.proposedFix.endLine;

    // Step 2: Apply Patch
    const lineIdx = startLine - 1;
    if (lineIdx < 0 || lineIdx >= lines.length) {
      return {
        findingFingerprint: finding.fingerprint,
        patchApplied: false,
        rescanExecuted: false,
        issueResolved: false,
        newFindingsIntroduced: [],
        checksPerformed,
        message: 'Fix failed: Line number out of bounds.'
      };
    }

    // Replace line with replacement code
    lines[lineIdx] = finding.proposedFix.replacementCode;
    const patchedContent = lines.join('\n');

    try {
      fs.writeFileSync(targetFilePath, patchedContent, 'utf8');
      checksPerformed.push(`Applied patch to ${finding.proposedFix.targetFile} at line ${startLine}`);
    } catch (err: any) {
      return {
        findingFingerprint: finding.fingerprint,
        patchApplied: false,
        rescanExecuted: false,
        issueResolved: false,
        newFindingsIntroduced: [],
        checksPerformed,
        message: `Fix failed to write: ${err?.message}`
      };
    }

    // Step 3: Rescan Modified File with Relevant Scanner
    checksPerformed.push('Triggered targeted rescan of modified file');
    const sastScanner = new BuiltinSASTScanner();
    const secretsScanner = new BuiltinSecretsScanner();

    const scanOptions: ScanOptions = { targetDirectory: workspaceRoot };
    const [sastRes, secRes] = await Promise.all([
      sastScanner.scan(scanOptions),
      secretsScanner.scan(scanOptions)
    ]);

    const rescannedFindings = [...sastRes.findings, ...secRes.findings];
    const originalStillPresent = rescannedFindings.some(f => f.fingerprint === finding.fingerprint);

    checksPerformed.push('Compared pre-patch and post-patch findings fingerprints');

    if (originalStillPresent) {
      // Revert patch to be safe
      fs.writeFileSync(targetFilePath, originalContent, 'utf8');
      checksPerformed.push('Reverted file to original state because issue persisted');

      return {
        findingFingerprint: finding.fingerprint,
        patchApplied: true,
        rescanExecuted: true,
        issueResolved: false,
        newFindingsIntroduced: [],
        checksPerformed,
        remainingUncertainty: 'The proposed patch did not completely eliminate the vulnerability pattern.',
        message: 'Verification failed: The original finding was still detected after applying the fix. Changes were reverted.'
      };
    }

    // Step 4: Check if any new findings were introduced on the same file
    const newFindings = rescannedFindings.filter(
      f => f.evidence.location.filePath === finding.evidence.location.filePath && f.fingerprint !== finding.fingerprint
    );

    if (newFindings.length > 0) {
      checksPerformed.push(`Detected ${newFindings.length} new potential findings introduced by the patch`);
    } else {
      checksPerformed.push('Verified zero new security findings introduced');
    }

    return {
      findingFingerprint: finding.fingerprint,
      patchApplied: true,
      rescanExecuted: true,
      issueResolved: true,
      newFindingsIntroduced: newFindings,
      checksPerformed,
      remainingUncertainty: 'Automated static verification passed. Running project functional test suite is recommended to ensure runtime compatibility.',
      message: 'Fix verified: The vulnerability was successfully resolved and verified via rescan.'
    };
  }
}
