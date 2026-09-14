import { isAbsolute, relative, resolve, win32 } from 'node:path';
import { parseJson, requireCondition } from './core.mjs';

export function diagnosticLocations(name, result, root, entries) {
  requireCondition(['gitleaks', 'trufflehog'].includes(name), 'unsupported-diagnostic-tool');
  const findings = name === 'gitleaks' ? parseJson(result.stdout)
    : result.stdout.split(/\r?\n/).filter(line => line.trim()).map(parseJson);
  const paths = new Map(entries.map(entry => [process.platform === 'win32'
    ? entry.path.toLowerCase() : entry.path, entry.path]));
  return findings.map(finding => {
    const detector = name === 'gitleaks' ? finding.RuleID : finding.DetectorName;
    requireCondition(typeof detector === 'string' && /^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$/.test(detector),
      'diagnostic-detector-schema');
    const metadata = finding.SourceMetadata?.Data?.Filesystem;
    const file = name === 'gitleaks' ? finding.File : metadata?.file;
    requireCondition(typeof file === 'string' && !/[\x00-\x1f\x7f]/.test(file),
      'diagnostic-location-schema');
    requireCondition(process.platform === 'win32' || !win32.isAbsolute(file), 'diagnostic-path-outside-snapshot');
    const path = relative(root, isAbsolute(file) ? file : resolve(root, file)).replaceAll('\\', '/');
    const approvedPath = paths.get(process.platform === 'win32' ? path.toLowerCase() : path);
    requireCondition(Boolean(approvedPath), 'diagnostic-path-outside-snapshot');
    const material = name === 'gitleaks' ? [finding.Secret, finding.Match] : [finding.Raw, finding.RawV2];
    requireCondition(!material.some(value => typeof value === 'string' && value.length > 0 &&
      (detector.includes(value) || approvedPath.includes(value))), 'diagnostic-metadata-contains-finding-material');
    const reportedLine = name === 'gitleaks' ? finding.StartLine : metadata?.line;
    const line = typeof reportedLine === 'string' && /^\d+$/.test(reportedLine)
      ? Number(reportedLine) : reportedLine;
    requireCondition(line === undefined || line === null || (Number.isSafeInteger(line) && line >= 0),
      'diagnostic-line-schema');
    return { detector, path: approvedPath, line: line > 0 ? line : null, synthetic: 'not-assessed' };
  });
}
