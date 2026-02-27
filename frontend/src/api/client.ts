import axios from "axios";
import type {
  Scan,
  ScanResponse,
  SubdomainResponse,
  EndpointResponse,
  SensitiveEndpoint,
} from "../types";

const api = axios.create({
  baseURL: "/api",
});

export async function startScan(domain: string): Promise<ScanResponse> {
  const { data } = await api.post<ScanResponse>("/scan", { domain });
  return data;
}

export async function getScans(): Promise<Scan[]> {
  const { data } = await api.get<Scan[]>("/scans");
  return data;
}

export async function getSubdomains(
  scanId: string
): Promise<SubdomainResponse[]> {
  const { data } = await api.get<SubdomainResponse[]>(
    `/scan/${scanId}/subdomains`
  );
  return data;
}

export async function getEndpoints(
  scanId: string
): Promise<EndpointResponse[]> {
  const { data } = await api.get<EndpointResponse[]>(
    `/scan/${scanId}/endpoints`
  );
  return data;
}

export async function getSensitiveEndpoints(
  scanId: string
): Promise<SensitiveEndpoint[]> {
  const { data } = await api.get<SensitiveEndpoint[]>(
    `/scan/${scanId}/sensitive`
  );
  return data;
}

export async function healthCheck(): Promise<{
  status: string;
  service: string;
}> {
  const { data } = await axios.get("/health");
  return data;
}
