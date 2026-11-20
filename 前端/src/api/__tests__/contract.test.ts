import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  API_CONTRACT,
  AUDIT_CHECK_NAMES,
  BENCHMARK_CATEGORIES,
  ENUM_CONTRACT,
  POLICIES,
  SCHEMA_CONTRACT,
} from '../contract';
import type {
  AuditCheck,
  AuditResult,
  BaselineResult,
  BatchDocInput,
  BatchDocSummary,
  BatchPreviewRequest,
  BatchPreviewResult,
  BenchmarkMetrics,
  BenchmarkResult,
  BenchmarkSample,
  BudgetErrorDetail,
  BudgetErrorResponse,
  HealthResult,
  IngestRequest,
  IngestResultModel,
  InvalidUTF8Detail,
  InvalidUTF8Response,
  Operation,
  Preset,
  TableNormalizeRequest,
  TableNormalizeResult,
  ThreatFinding,
  ThreatInspectRequest,
  ThreatInspectResult,
  ValidationErrorResponse,
  ValidationIssue,
} from '../types';

type Schema = {
  type?: string;
  enum?: readonly unknown[];
  const?: unknown;
  anyOf?: Schema[];
  items?: Schema;
  properties?: Record<string, Schema>;
  propertyNames?: Schema;
  additionalProperties?: boolean | Schema;
  required?: string[];
  $ref?: string;
};
type OperationSchema = {
  requestBody?: { content: { 'application/json': { schema: Schema } }; required?: boolean };
  responses: Record<string, { content: { 'application/json': { schema: Schema } } }>;
};
type OpenApiDocument = {
  paths: Record<string, Record<string, OperationSchema>>;
  components: { schemas: Record<string, Schema> };
};

const document = JSON.parse(
  readFileSync(resolve(process.cwd(), '../后端/docs/openapi.json'), 'utf8'),
) as OpenApiDocument;
const schemas = document.components.schemas;

const refName = (schema: Schema) => schema.$ref?.replace('#/components/schemas/', '');

function flattenedEnums(schema: Schema): unknown[] {
  return [
    ...(schema.enum ?? []),
    ...(schema.const === undefined ? [] : [schema.const]),
    ...(schema.anyOf ?? []).flatMap(flattenedEnums),
  ];
}

type ContractTypeMap = {
  AuditCheck: AuditCheck;
  AuditResult: AuditResult;
  BaselineResult: BaselineResult;
  BatchDocInput: BatchDocInput;
  BatchDocSummary: BatchDocSummary;
  BatchPreviewRequest: BatchPreviewRequest;
  BatchPreviewResult: BatchPreviewResult;
  BenchmarkMetrics: BenchmarkMetrics;
  BenchmarkResult: BenchmarkResult;
  BenchmarkSample: BenchmarkSample;
  BudgetErrorDetail: BudgetErrorDetail;
  BudgetErrorResponse: BudgetErrorResponse;
  HealthResult: HealthResult;
  IngestRequest: IngestRequest;
  IngestResultModel: IngestResultModel;
  InvalidUTF8Detail: InvalidUTF8Detail;
  InvalidUTF8Response: InvalidUTF8Response;
  Operation: Operation;
  Preset: Preset;
  TableNormalizeRequest: TableNormalizeRequest;
  TableNormalizeResult: TableNormalizeResult;
  ThreatFinding: ThreatFinding;
  ThreatInspectRequest: ThreatInspectRequest;
  ThreatInspectResult: ThreatInspectResult;
  ValidationErrorResponse: ValidationErrorResponse;
  ValidationIssue: ValidationIssue;
};
type RequiredKeys<T> = { [K in keyof T]-?: object extends Pick<T, K> ? never : K }[keyof T];
type DeclaredKeys = keyof typeof SCHEMA_CONTRACT;
type MissingFromTypes = Exclude<keyof ContractTypeMap, DeclaredKeys>;
type ExtraInTypes = Exclude<DeclaredKeys, keyof ContractTypeMap>;
type MissingRequired = {
  [K in DeclaredKeys & keyof ContractTypeMap]: Exclude<
    RequiredKeys<ContractTypeMap[K]>,
    (typeof SCHEMA_CONTRACT)[K]['required'][number]
  >;
}[DeclaredKeys & keyof ContractTypeMap];
type InvalidRequired = {
  [K in DeclaredKeys & keyof ContractTypeMap]: Exclude<
    (typeof SCHEMA_CONTRACT)[K]['required'][number],
    RequiredKeys<ContractTypeMap[K]>
  >;
}[DeclaredKeys & keyof ContractTypeMap];
function assertNever<T extends never>(value?: T) {
  return value;
}
assertNever<MissingFromTypes | ExtraInTypes | MissingRequired | InvalidRequired>();

describe('OpenAPI endpoint contract', () => {
  it('contains exactly all eight endpoint methods, bodies and responses', () => {
    expect(Object.keys(document.paths).sort()).toEqual(
      API_CONTRACT.map((endpoint) => endpoint.path).sort(),
    );

    for (const endpoint of API_CONTRACT) {
      const path = document.paths[endpoint.path];
      expect(Object.keys(path), endpoint.path).toEqual([endpoint.method.toLowerCase()]);
      const operation = path[endpoint.method.toLowerCase()];
      const requestSchema = operation.requestBody?.content['application/json'].schema;
      if ('requestSchema' in endpoint) {
        expect(refName(requestSchema ?? {}), endpoint.path).toBe(endpoint.requestSchema);
        expect(operation.requestBody?.required).toBe(true);
      } else {
        expect(operation.requestBody, endpoint.path).toBeUndefined();
      }

      const responseSchema = operation.responses['200'].content['application/json'].schema;
      if ('responseArray' in endpoint && endpoint.responseArray) {
        expect(responseSchema.type).toBe('array');
        expect(refName(responseSchema.items ?? {})).toBe(endpoint.responseSchema);
      } else {
        expect(refName(responseSchema), endpoint.path).toBe(endpoint.responseSchema);
      }
      expect(Object.keys(operation.responses).sort(), endpoint.path).toEqual(
        [...endpoint.errorStatuses, '200'].sort(),
      );
      if (endpoint.errorStatuses.includes('400')) {
        expect(refName(operation.responses['400'].content['application/json'].schema)).toBe(
          'InvalidUTF8Response',
        );
      }
      if (endpoint.errorStatuses.includes('413')) {
        expect(refName(operation.responses['413'].content['application/json'].schema)).toBe(
          'BudgetErrorResponse',
        );
      }
      if (endpoint.errorStatuses.includes('422')) {
        expect(refName(operation.responses['422'].content['application/json'].schema)).toBe(
          'ValidationErrorResponse',
        );
      }
    }
  });
});

describe('OpenAPI model contract', () => {
  it('matches every schema name and required field list, including optional defaults', () => {
    expect(Object.keys(schemas).sort()).toEqual(Object.keys(SCHEMA_CONTRACT).sort());
    for (const [name, contract] of Object.entries(SCHEMA_CONTRACT)) {
      const schema = schemas[name];
      expect([...(schema.required ?? [])].sort(), `${name}.required`).toEqual(
        [...contract.required].sort(),
      );
      for (const field of contract.required) {
        expect(schema.properties, `${name}.${field}`).toHaveProperty(field);
      }
    }
  });

  it('matches every scalar enum and const with the TypeScript union sources', () => {
    const discovered = new Set<string>();
    for (const [name, schema] of Object.entries(schemas)) {
      for (const [field, property] of Object.entries(schema.properties ?? {})) {
        const values = flattenedEnums(property);
        if (values.length > 0) discovered.add(`${name}.${field}`);
      }
    }
    expect([...discovered].sort()).toEqual(Object.keys(ENUM_CONTRACT).sort());

    for (const [key, expected] of Object.entries(ENUM_CONTRACT)) {
      const [name, field] = key.split('.');
      expect(flattenedEnums(schemas[name].properties?.[field] ?? {}), key).toEqual([...expected]);
    }
    expect(POLICIES).toEqual(ENUM_CONTRACT['IngestRequest.policy']);
    expect(AUDIT_CHECK_NAMES).toEqual(ENUM_CONTRACT['AuditCheck.name']);
    expect(BENCHMARK_CATEGORIES).toEqual(ENUM_CONTRACT['BenchmarkSample.category']);
  });

  it('matches benchmark map-key enums and request additionalProperties=false', () => {
    expect(schemas.BenchmarkResult.properties?.modes.propertyNames?.enum).toEqual([...POLICIES]);
    expect(schemas.BenchmarkResult.properties?.by_category.propertyNames?.enum).toEqual([
      ...BENCHMARK_CATEGORIES,
    ]);
    const categoryModes = schemas.BenchmarkResult.properties?.by_category.additionalProperties;
    expect(typeof categoryModes).toBe('object');
    expect((categoryModes as Schema).propertyNames?.enum).toEqual([...POLICIES]);

    for (const endpoint of API_CONTRACT) {
      if (endpoint.requestSchema !== undefined) {
        expect(schemas[endpoint.requestSchema].additionalProperties, endpoint.path).toBe(false);
      }
    }
  });
});
