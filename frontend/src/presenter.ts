import { Node } from "./api/client";

export interface Badge {
  text: string;
  tone: "danger" | "warn" | "ok";
}

export interface PropRow {
  key: string;
  value: string;
}

// campos internos que nunca devem aparecer na UI
const HIDDEN = new Set([
  "uid", "icon", "name", "label", "id",
  "exposes_world", "exposes_ssh_world", "exposes_http_world", "exposes_rdp_world",
  "inbound_world_ports", "sg_ids",
]);

// rótulo amigável por propriedade
const LABELS: Record<string, string> = {
  user_name: "Usuário",
  role_name: "Role",
  policy_name: "Política",
  bucket_name: "Bucket",
  instance_id: "Instância",
  db_id: "Banco",
  function_name: "Função",
  group_id: "Security Group",
  vpc_id: "VPC",
  igw_id: "Internet Gateway",
  account_id: "Conta",
  region: "Região",
  state: "Estado",
  public_ip: "IP público",
  private_ip: "IP privado",
  engine: "Engine",
  runtime: "Runtime",
  cidr_block: "CIDR",
  arn: "ARN",
  iam_instance_profile: "Instance profile",
  inbound_ports: "Portas abertas",
  inbound_cidrs: "Origens (CIDR)",
};

export function badges(n: Node): Badge[] {
  const p = n.properties as Record<string, unknown>;
  const out: Badge[] = [];
  if (p.exposes_ssh_world) out.push({ text: "SSH aberto à internet", tone: "danger" });
  if (p.exposes_rdp_world) out.push({ text: "RDP aberto à internet", tone: "danger" });
  if (p.exposes_http_world) out.push({ text: "HTTP aberto à internet", tone: "warn" });
  if (p.exposes_world && !p.exposes_ssh_world && !p.exposes_rdp_world && !p.exposes_http_world)
    out.push({ text: "Exposto à internet", tone: "warn" });
  if (p.is_public) out.push({ text: "Público", tone: "danger" });
  if (p.publicly_accessible) out.push({ text: "Acessível publicamente", tone: "danger" });
  if (p.has_mfa === false) out.push({ text: "Sem MFA", tone: "warn" });
  if (p.encrypted === false) out.push({ text: "Sem criptografia", tone: "warn" });
  if (p.encryption === "none") out.push({ text: "Sem criptografia", tone: "warn" });
  if (n.label === "InternetGateway") out.push({ text: "Ponto de entrada", tone: "warn" });
  if (p.public_ip) out.push({ text: "Tem IP público", tone: "warn" });
  // CVE / imagem
  if (n.label === "CVE" && p.severity) {
    const sev = String(p.severity);
    out.push({ text: sev, tone: sev === "CRITICAL" || sev === "HIGH" ? "danger" : "warn" });
    if (p.fixed_version) out.push({ text: `fix: ${p.fixed_version}`, tone: "ok" });
  }
  if (n.label === "ContainerImage") {
    const crit = Number(p.critical_count || 0);
    const total = Number(p.cve_count || 0);
    if (crit > 0) out.push({ text: `${crit} CVE crítica(s)`, tone: "danger" });
    else if (total > 0) out.push({ text: `${total} CVE(s)`, tone: "warn" });
  }
  if (n.label === "ServiceAccount" && p.role_arn) {
    out.push({ text: "IRSA → IAM role", tone: "warn" });
  }
  return out;
}

export function displayName(n: Node): string {
  const p = n.properties as Record<string, unknown>;
  if (p.image_ref) return `${p.repo}:${p.tag}`;
  return String(
    p.user_name || p.role_name || p.policy_name || p.bucket_name || p.instance_id ||
    p.db_id || p.function_name || p.group_id || p.vpc_id || p.igw_id || p.account_id ||
    p.cve_id || p.name || n.id
  );
}

export function props(n: Node): PropRow[] {
  const p = n.properties as Record<string, unknown>;
  const rows: PropRow[] = [];
  for (const [k, v] of Object.entries(p)) {
    if (HIDDEN.has(k)) continue;
    if (k.startsWith("exposes_")) continue;
    if (v === null || v === undefined || v === "") continue;
    if (Array.isArray(v) && v.length === 0) continue;
    rows.push({ key: LABELS[k] || k, value: fmtValue(v) });
  }
  return rows;
}

function fmtValue(v: unknown): string {
  if (Array.isArray(v)) return v.join(", ");
  if (typeof v === "boolean") return v ? "sim" : "não";
  return String(v);
}
