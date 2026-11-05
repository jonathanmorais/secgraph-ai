from fastapi import APIRouter
from fastapi.responses import Response

from graphsec.reports.compliance import generate_bacen_report

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/bacen-4893")
def bacen_report() -> Response:
    pdf_bytes = generate_bacen_report()
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="bacen-4893.pdf"'},
    )
