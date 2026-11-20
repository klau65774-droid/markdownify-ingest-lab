import type { Operation, OperationKind, Severity, ThreatFinding } from '../../api/types';

export type AuditStage = 'PRE' | 'DOM' | 'TABLE' | 'LINK' | 'POST';
export type AuditOperation = Operation & {
  stage: AuditStage;
  op: OperationKind;
  actionLabel: string;
  risk: Uppercase<Severity>;
};

const stageByKind: Record<OperationKind, AuditStage> = {
  STRIP_DANGEROUS_URI: 'LINK',
  STRIP_TRACKING_PIXEL: 'LINK',
  CLEAN_TRACKING_URL: 'LINK',
  STRIP_HIDDEN_STYLE: 'PRE',
  STRIP_HIDDEN_ATTR: 'PRE',
  STRIP_ZERO_WIDTH: 'PRE',
  STRIP_SUSPICIOUS_ATTRIBUTE: 'PRE',
  STRIP_INSTRUCTION: 'PRE',
  PRUNE_BOILERPLATE: 'DOM',
  REDACT_SECRET: 'POST',
  NORMALIZE_TABLE: 'TABLE',
};

const defaultRisk: Record<OperationKind, Uppercase<Severity>> = {
  STRIP_DANGEROUS_URI: 'CRITICAL',
  STRIP_TRACKING_PIXEL: 'MEDIUM',
  CLEAN_TRACKING_URL: 'LOW',
  STRIP_HIDDEN_STYLE: 'CRITICAL',
  STRIP_HIDDEN_ATTR: 'CRITICAL',
  STRIP_ZERO_WIDTH: 'HIGH',
  STRIP_SUSPICIOUS_ATTRIBUTE: 'HIGH',
  STRIP_INSTRUCTION: 'CRITICAL',
  PRUNE_BOILERPLATE: 'MEDIUM',
  REDACT_SECRET: 'HIGH',
  NORMALIZE_TABLE: 'LOW',
};

const severityRank: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

export function toAuditOperations(operations: Operation[], threats: ThreatFinding[]): AuditOperation[] {
  return operations.map((operation) => {
    const matchingThreat = threats
      .filter((threat) => threat.dom_path === operation.dom_path)
      .sort((a, b) => severityRank[b.severity] - severityRank[a.severity])[0];
    return {
      ...operation,
      stage: stageByKind[operation.kind],
      op: operation.kind,
      actionLabel: operation.kind === 'NORMALIZE_TABLE' ? 'EXPAND_TABLE_SPAN' : operation.kind,
      risk: matchingThreat?.severity.toUpperCase() as Uppercase<Severity> | undefined ?? defaultRisk[operation.kind],
    };
  });
}
