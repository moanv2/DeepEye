export interface Scan {
  id: string;
  domain: string;
  status: string;
  progress: number;
  created_at: string;
  subdomains_count: number;
  endpoints_count: number;
  sensitive_count: number;
}

export interface ScanResponse {
  id: string;
  domain: string;
  status: string;
  progress: number;
  created_at: string;
  subdomains_count: number;
  alive_count: number;
  dead_count: number;
  endpoints_count: number;
  sensitive_count: number;
}

export interface SubdomainResponse {
  row_num: number;
  id: string;
  subdomain: string;
  ip_address: string | null;
  host_status: number;
  asn: string | null;
  asn_org: string | null;
  discovered_at: string;
}

export interface EndpointResponse {
  row_num: number;
  id: string;
  url: string;
  path: string | null;
  method: string;
  status_code: number | null;
  is_sensitive: boolean;
  sensitivity_reason: string | null;
  discovered_at: string;
}

export interface SensitiveEndpoint {
  url: string;
  path: string | null;
  reason: string | null;
  status_code: number | null;
}
