// SVG line-icons por tipo de recurso. Cada entrada é o conteúdo interno de
// um <svg viewBox="0 0 24 24">, desenhado com stroke (sem fill).

const PATHS: Record<string, string> = {
  // identidade
  IAMUser: '<circle cx="12" cy="8" r="3.4"/><path d="M5.5 19.5c0-3.6 2.9-6.2 6.5-6.2s6.5 2.6 6.5 6.2"/>',
  IAMRole:
    '<rect x="3.5" y="4.5" width="17" height="15" rx="2"/><circle cx="12" cy="10" r="2.3"/><path d="M8 16.5c0-2.1 1.8-3.4 4-3.4s4 1.3 4 3.4"/>',
  IAMPolicy:
    '<path d="M7 3.5h7l4 4v13H7z"/><path d="M14 3.5v4h4"/><path d="M9.5 12.5h5M9.5 15.5h5"/>',
  AWSAccount:
    '<path d="M7 18a4 4 0 0 1-.6-8 5.2 5.2 0 0 1 9.9-1.3A3.6 3.6 0 0 1 17 18z"/>',
  // compute
  EC2Instance:
    '<rect x="4" y="4.5" width="16" height="6.5" rx="1"/><rect x="4" y="13" width="16" height="6.5" rx="1"/><path d="M7 7.7h.01M7 16.2h.01"/>',
  LambdaFunction: '<path d="M6.5 19.5L12 4.5h2.2l5 15"/><path d="M9 12.5l2.4-6"/>',
  // storage
  S3Bucket: '<path d="M4.5 6h15l-1.7 13.3a1 1 0 0 1-1 .9H7.2a1 1 0 0 1-1-.9z"/><path d="M4 6h16"/>',
  RDSInstance:
    '<ellipse cx="12" cy="6" rx="7" ry="3"/><path d="M5 6v12c0 1.7 3.1 3 7 3s7-1.3 7-3V6"/><path d="M5 12c0 1.7 3.1 3 7 3s7-1.3 7-3"/>',
  // rede
  VPC: '<rect x="3.5" y="3.5" width="17" height="17" rx="2"/><path d="M8 8h8v8H8z"/>',
  Subnet: '<rect x="4" y="4" width="16" height="16" rx="1"/><path d="M4 12h16M12 4v16"/>',
  InternetGateway:
    '<circle cx="12" cy="12" r="8"/><path d="M4 12h16"/><path d="M12 4c2.6 2.6 2.6 13.4 0 16M12 4c-2.6 2.6-2.6 13.4 0 16"/>',
  SecurityGroup: '<path d="M12 3.5l7 2.8V11c0 4.6-3 7.7-7 9.2-4-1.5-7-4.6-7-9.2V6.3z"/>',
  // service principal (engrenagem)
  ServicePrincipal:
    '<circle cx="12" cy="12" r="3"/><path d="M12 3v2.5M12 18.5V21M4.2 7.5l2.2 1.3M17.6 15.2l2.2 1.3M4.2 16.5l2.2-1.3M17.6 8.8l2.2-1.3"/>',
  // kubernetes / workloads
  Pod: '<path d="M12 3l7.5 4.3v8.6L12 20.2 4.5 15.9V7.3z"/><circle cx="12" cy="11.7" r="2.4"/>',
  Container:
    '<rect x="3.5" y="7" width="17" height="11" rx="1"/><path d="M3.5 11h17M8 7V5h8v2"/>',
  ContainerImage:
    '<rect x="3.5" y="5.5" width="17" height="13" rx="1.5"/><path d="M3.5 10h17"/><circle cx="7" cy="7.7" r="0.6"/>',
  CVE: '<path d="M12 3l9 16H3z"/><path d="M12 9.5v4.5M12 16.8h.01"/>',
  ServiceAccount:
    '<circle cx="12" cy="8" r="3.2"/><path d="M5.5 19c0-3.5 2.9-6 6.5-6s6.5 2.5 6.5 6"/><path d="M15.5 4.5l1.5 1.5 3-3"/>',
  // achados
  Finding: '<path d="M12 4l8.5 15H3.5z"/><path d="M12 10v4.5M12 17.2h.01"/>',
};

const FALLBACK = '<circle cx="12" cy="12" r="7"/>';

export function iconFor(label: string, color: string): string {
  const inner = PATHS[label] || FALLBACK;
  const svg =
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" ` +
    `fill="none" stroke="${color}" stroke-width="1.7" ` +
    `stroke-linecap="round" stroke-linejoin="round">${inner}</svg>`;
  return "data:image/svg+xml;utf8," + encodeURIComponent(svg);
}
