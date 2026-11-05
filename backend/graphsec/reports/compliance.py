"""Compliance report generation (BACEN 4893, LGPD)."""
import io
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table

from graphsec.graph.client import run_read


def generate_bacen_report() -> bytes:
    """Gera relatorio de conformidade BACEN Resolucao 4893."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("Relatorio de Conformidade - BACEN 4893", styles["Title"]),
        Paragraph(f"Gerado em: {datetime.utcnow().isoformat()}Z", styles["Normal"]),
        Spacer(1, 20),
    ]

    sections = [
        ("Usuarios IAM sem MFA",
         "MATCH (u:IAMUser {has_mfa: false}) RETURN u.user_name AS user_name, u.arn AS arn LIMIT 100"),
        ("Buckets S3 publicos",
         "MATCH (b:S3Bucket {is_public: true}) RETURN b.bucket_name AS bucket, b.region AS region LIMIT 100"),
        ("RDS acessivel publicamente",
         "MATCH (d:RDSInstance {publicly_accessible: true}) RETURN d.db_id AS db_id, d.engine AS engine LIMIT 100"),
        ("RDS nao criptografado",
         "MATCH (d:RDSInstance {encrypted: false}) RETURN d.db_id AS db_id, d.engine AS engine LIMIT 100"),
    ]

    for title, cypher in sections:
        story.append(Paragraph(title, styles["Heading2"]))
        try:
            rows = run_read(cypher)
        except Exception as e:
            story.append(Paragraph(f"Erro ao executar: {e}", styles["Normal"]))
            story.append(Spacer(1, 12))
            continue
        if not rows:
            story.append(Paragraph("Nenhum achado.", styles["Normal"]))
        else:
            headers = list(rows[0].keys())
            data = [headers] + [[str(r.get(h, "")) for h in headers] for r in rows]
            story.append(Table(data))
        story.append(Spacer(1, 16))

    doc.build(story)
    return buf.getvalue()
