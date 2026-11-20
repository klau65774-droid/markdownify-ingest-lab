"""FastAPI entry point. The OpenAPI artifact is exported from app.openapi()."""

from time import perf_counter_ns

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ..baseline import BASELINE_VERSION
from ..guard import MAX_BYTES, BudgetExceededError, HTMLInputError, redact_secrets
from . import service
from .benchmark import run_benchmark
from .models import (
    MAX_BATCH_DOCUMENTS,
    AuditResult,
    BatchPreviewRequest,
    BatchPreviewResult,
    BenchmarkResult,
    BudgetErrorResponse,
    HealthResult,
    IngestRequest,
    IngestResultModel,
    InvalidUTF8Response,
    Preset,
    TableNormalizeRequest,
    TableNormalizeResult,
    ThreatInspectRequest,
    ThreatInspectResult,
    ValidationErrorResponse,
)
from .presets import PRESETS

# JSON can use six wire bytes for a single decoded ASCII byte (an escaped code point).
_HTML_BODY_LIMIT = 6 * MAX_BYTES + 4096
_BATCH_BODY_LIMIT = MAX_BATCH_DOCUMENTS * (6 * MAX_BYTES + 1024) + 4096
_START_TIME = perf_counter_ns()
_ERROR_RESPONSES: dict[int | str, dict[str, object]] = {
    400: {"model": InvalidUTF8Response, "description": "Invalid UTF-8 request"},
    413: {"model": BudgetErrorResponse, "description": "Input or conversion exceeds a resource budget"},
    422: {"model": ValidationErrorResponse, "description": "Request validation failed"},
}


def _budget_response(error: BudgetExceededError) -> JSONResponse:
    return JSONResponse(
        {"detail": {"code": error.code, "limit": error.limit, "observed": error.observed}}, status_code=413,
    )


def _utf8_response() -> JSONResponse:
    return JSONResponse({"detail": {"code": "invalid_utf8"}}, status_code=400)


class _RequestBudgetMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] != "POST":
            await self.app(scope, receive, send)
            return

        limit = _BATCH_BODY_LIMIT if scope["path"] == "/api/batch/preview" else _HTML_BODY_LIMIT
        headers = Headers(scope=scope)
        media_type = headers.get("content-type", "").partition(";")[0].strip().lower()
        if media_type and media_type != "application/json" and not media_type.endswith("+json"):
            limit = MAX_BYTES
        length = headers.get("content-length", "")
        if length.isascii() and length.isdecimal():
            digits = length.lstrip("0")
            # A huge header must not reach Python's integer parser.
            declared = int(digits or "0") if len(digits) <= 18 else limit + 1
            if declared > limit:
                await _budget_response(BudgetExceededError("max_bytes", limit, declared))(scope, receive, send)
                return

        buffer = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            observed = len(buffer) + len(chunk)
            if observed > limit:
                await _budget_response(BudgetExceededError("max_bytes", limit, observed))(scope, receive, send)
                return
            buffer.extend(chunk)
            if not message.get("more_body", False):
                break

        body = bytes(buffer)
        del buffer
        try:
            body.decode("utf-8")
        except UnicodeDecodeError:
            await _utf8_response()(scope, receive, send)
            return

        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if replayed:
                return await receive()
            replayed = True
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(scope, replay, send)


app = FastAPI(
    title="Markdownify Ingestion Workbench", version=BASELINE_VERSION,
    openapi_url=None, docs_url=None, redoc_url=None, redirect_slashes=False,
)
app.add_middleware(_RequestBudgetMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_methods=["GET", "POST"], allow_headers=["Content-Type"],
)


@app.exception_handler(BudgetExceededError)
async def budget_error(_request: Request, exc: BudgetExceededError) -> JSONResponse:
    return _budget_response(exc)


@app.exception_handler(UnicodeError)
async def invalid_utf8(_request: Request, _exc: UnicodeError) -> JSONResponse:
    return _utf8_response()


@app.exception_handler(HTMLInputError)
async def invalid_html(_request: Request, exc: HTMLInputError) -> JSONResponse:
    return JSONResponse(
        {"detail": [{"type": "html_input", "loc": ["body", "html"], "msg": str(exc)}]}, status_code=422,
    )


def _safe_error_text(value: str) -> str:
    return redact_secrets(value)[0].encode("utf-8", errors="replace").decode("utf-8")


@app.exception_handler(RequestValidationError)
async def validation_error(_request: Request, exc: RequestValidationError) -> JSONResponse:
    details = [
        {
            "type": error["type"],
            "loc": [part if isinstance(part, int) else _safe_error_text(str(part)) for part in error["loc"]],
            "msg": _safe_error_text(error["msg"]),
        }
        for error in exc.errors()
    ]
    return JSONResponse({"detail": details}, status_code=422)


@app.get("/api/health")
def health() -> HealthResult:
    return HealthResult(
        version=BASELINE_VERSION, uptime_ms=(perf_counter_ns() - _START_TIME) // 1_000_000,
        preset_count=len(PRESETS),
        engine_capabilities=dict.fromkeys((
            "resource_budgets", "uri_sanitizer", "secret_redaction", "indirect_prompt_guard",
            "boilerplate_pruning", "table_normalization", "code_language_inference", "baseline_comparison",
        ), True),
    )


@app.get("/api/presets", response_model=list[Preset])
def presets() -> tuple[Preset, ...]:
    return PRESETS


@app.post("/api/ingest", responses=_ERROR_RESPONSES)
def ingest(request: IngestRequest) -> IngestResultModel:
    return service.ingest(request)


@app.post("/api/inspect/threats", responses=_ERROR_RESPONSES)
def inspect_threats(request: ThreatInspectRequest) -> ThreatInspectResult:
    return service.threat_inspection(request.html)


@app.post("/api/tables/normalize", responses=_ERROR_RESPONSES)
def normalize_tables(request: TableNormalizeRequest) -> TableNormalizeResult:
    return service.table_normalization(request.html)


@app.post("/api/benchmarks/run", responses=_ERROR_RESPONSES)
def benchmarks() -> BenchmarkResult:
    return run_benchmark()


@app.post("/api/dos/audit", responses=_ERROR_RESPONSES)
def dos_audit() -> AuditResult:
    return service.run_dos_audit()


@app.post("/api/batch/preview", responses=_ERROR_RESPONSES)
def batch_preview(request: BatchPreviewRequest) -> BatchPreviewResult:
    return service.batch_preview(request)
