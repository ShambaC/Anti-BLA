import catalog from '../data/rea-failure-patterns.json' with { type: 'json' };

export interface CatalogPattern {
  id: string;
  match: {
    code?: string;
    operation?: string;
    detailsLimitSetting?: string;
    detailsResource?: string;
    hasPartialObservation?: boolean;
    resourceLimitValues?: string[];
  };
  alsoMatchText: string[];
  category: string;
  documentation: string[];
}

export const CATALOG_UPSTREAM = catalog.upstream;
export const PATTERNS: CatalogPattern[] = catalog.patterns as CatalogPattern[];

type LimitKey = keyof typeof catalog.limits;
/** Pinned upstream limit; callers must word results as "per rea-agents <version> source". */
export function limit(key: LimitKey): number {
  return catalog.limits[key].value;
}
export function limitSource(key: LimitKey): string {
  return `${catalog.limits[key].source} (rea-agents ${catalog.upstream.upstream_version}, verified ${catalog.upstream.verified_at})`;
}
