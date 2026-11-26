from __future__ import annotations

import hashlib
import re
import uuid
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import httpx

from xssam.config import XSSAMSettings, load_config
from xssam.core.models import (
    Finding,
    FindingStatus,
    Parameter,
    ParameterLocation,
    Payload,
    ProofOfConcept,
)
from xssam.logging import ScanLogger
from xssam.payloads.corpus import ContextAnalyzer, PayloadCorpus
from xssam.payloads.encodings import PayloadMutator
from xssam.utils.http import AsyncHttpClient

DOM_SINK_PATTERN = re.compile(
    r"location\.(?:hash|search)|document\.write|innerHTML|outerHTML|eval\s*\(|setTimeout\s*\(",
    re.IGNORECASE,
)


class ReflectionChecker:
    """Only raw/case variants count as potentially executable reflections.

    Checking just for a canary token reported HTML-escaped output as XSS. The
    browser validator remains the authority on actual execution.
    """

    def check(self, response_text: str, payload_text: str) -> bool:
        if not payload_text:
            return False
        if payload_text in response_text:
            return True
        return payload_text.casefold() in response_text.casefold()


class XSSScanner:
    def __init__(
        self,
        client: AsyncHttpClient,
        config: XSSAMSettings | None = None,
        logger: ScanLogger | None = None,
    ) -> None:
        self.client = client
        self.config = config or load_config(cwd_fallback=False)
        self.logger = logger or ScanLogger(quiet=True)
        self.corpus = PayloadCorpus()
        self.analyzer = ContextAnalyzer()
        # A per-scan token prevents unrelated page content or alert() calls
        # from being mistaken for payload execution.
        self.marker = f"XSSAM_{uuid.uuid4().hex[:12]}"
        self.ref_checker = ReflectionChecker()
        self.mutator = PayloadMutator()

    async def scan_parameter(
        self,
        url: str,
        parameter: Parameter,
        *,
        validator: Any | None = None,
        response_text: str | None = None,
    ) -> list[Finding]:
        del response_text  # reserved for future per-context optimization
        if not self.config.scanner.reflected:
            return []

        effective_url = parameter.action_url or url
        if parameter.location == ParameterLocation.FRAGMENT:
            return await self._scan_fragment(effective_url, parameter, validator)
        if parameter.location == ParameterLocation.JAVASCRIPT:
            return []

        canary_response = await self._perform_injection(
            effective_url, parameter, self.analyzer.canary
        )
        if canary_response is None:
            return []
        context = self.analyzer.analyze(canary_response.text)
        if context == "unknown":
            return []

        payloads = self.corpus.get_payloads(context, self.marker)
        limit = min(
            len(payloads),
            self.config.scanner.max_payloads_per_parameter
            if self.config.scanner.comprehensive_payloads
            else 3,
        )
        best_potential: Finding | None = None
        seen_rendered: set[str] = set()

        for payload in payloads[:limit]:
            for rendered in self.mutator.mutate(payload.text):
                if rendered in seen_rendered:
                    continue
                seen_rendered.add(rendered)

                poc = self._build_poc(effective_url, parameter, rendered)
                if poc is None:
                    continue
                response = await self._request_poc(poc)
                if response is None or not self.ref_checker.check(response.text, rendered):
                    continue

                finding = self._make_finding(
                    url=url,
                    parameter=parameter,
                    payload=payload,
                    rendered=rendered,
                    context=context,
                    poc=poc,
                    response=response,
                )
                status = await self._validate(finding, validator)
                self._apply_status(finding, status)
                if finding.status == FindingStatus.CONFIRMED:
                    return [finding]
                if best_potential is None:
                    best_potential = finding
                if validator is None:
                    return [best_potential]
                break  # one reflected variant per payload is enough

        return [best_potential] if best_potential else []

    async def scan_dom_fragment(
        self,
        url: str,
        response_text: str,
        validator: Any | None,
    ) -> list[Finding]:
        """Probe obvious client-side sinks with a fragment payload.

        This mode requires browser validation: an HTTP response cannot contain
        a fragment because browsers never send fragments to the server.
        """
        if (
            not self.config.scanner.dom
            or validator is None
            or not response_text
            or not DOM_SINK_PATTERN.search(response_text)
        ):
            return []
        parameter = Parameter(
            name="__xssam_dom_probe__",
            value="",
            location=ParameterLocation.FRAGMENT,
            discovery_source="DOM sink heuristic",
        )
        return await self._scan_fragment(url, parameter, validator)

    async def _scan_fragment(
        self,
        url: str,
        parameter: Parameter,
        validator: Any | None,
    ) -> list[Finding]:
        if validator is None:
            return []
        for payload in self.corpus.get_payloads("dom", self.marker)[:3]:
            rendered = payload.text
            poc = self._build_poc(url, parameter, rendered)
            if poc is None:
                continue
            finding = self._make_finding(
                url=url,
                parameter=parameter,
                payload=payload,
                rendered=rendered,
                context="dom",
                poc=poc,
                response=None,
                probe="DOM fragment",
            )
            status = await self._validate(finding, validator)
            if status == FindingStatus.CONFIRMED:
                self._apply_status(finding, status)
                return [finding]
        return []

    async def _validate(self, finding: Finding, validator: Any | None) -> Any:
        if validator is None:
            return FindingStatus.POTENTIAL
        try:
            result = validator.validate(finding)
            if hasattr(result, "__await__"):
                result = await result
            return result or FindingStatus.POTENTIAL
        except Exception as exc:
            self.logger.debug(f"Browser validation failed: {exc}")
            return FindingStatus.POTENTIAL

    @staticmethod
    def _apply_status(finding: Finding, status: Any) -> None:
        try:
            finding.status = FindingStatus(status)
        except (TypeError, ValueError):
            finding.status = FindingStatus.POTENTIAL
        if finding.status == FindingStatus.CONFIRMED:
            finding.severity = "High"
            finding.confidence = "High"
        else:
            finding.severity = "Medium"
            finding.confidence = "Low"

    async def _perform_injection(
        self,
        url: str,
        parameter: Parameter,
        payload: str,
    ) -> httpx.Response | None:
        poc = self._build_poc(url, parameter, payload)
        if poc is None:
            return None
        return await self._request_poc(poc)

    async def _request_poc(self, poc: ProofOfConcept) -> httpx.Response | None:
        kwargs: dict[str, Any] = {}
        if poc.headers:
            kwargs["headers"] = poc.headers
        if poc.cookies:
            kwargs["cookies"] = poc.cookies
        if poc.method == "POST" and poc.data is not None:
            kwargs["data"] = poc.data
        return await self.client.request(poc.method, poc.url, **kwargs)

    def _build_poc(
        self,
        url: str,
        parameter: Parameter,
        payload: str,
    ) -> ProofOfConcept | None:
        parsed = urlsplit(url)
        method = "GET"
        request_url = url
        data: dict[str, str] | None = None
        headers: dict[str, str] = {}
        cookies: dict[str, str] = {}

        if parameter.location == ParameterLocation.QUERY:
            request_url = self._inject_query(url, parameter.name, payload)
        elif parameter.location == ParameterLocation.PATH:
            injected = self._inject_path(url, parameter.name, payload)
            if injected == url:
                return None
            request_url = injected
        elif parameter.location in {ParameterLocation.FORM, ParameterLocation.BODY}:
            method = parameter.method.upper()
            if method == "GET":
                request_url = self._inject_query(url, parameter.name, payload)
            else:
                data = {parameter.name: payload}
        elif parameter.location == ParameterLocation.HEADER:
            headers[parameter.name] = payload
        elif parameter.location == ParameterLocation.COOKIE:
            cookies[parameter.name] = payload
        elif parameter.location == ParameterLocation.FRAGMENT:
            request_url = urlunsplit(
                parsed._replace(fragment=quote(payload, safe=""))
            )
        else:
            return None

        return ProofOfConcept(
            method=method,
            url=request_url,
            data=data,
            headers=headers,
            cookies=cookies,
        )

    @staticmethod
    def _inject_query(url: str, name: str, payload: str) -> str:
        parsed = urlsplit(url)
        pairs = [
            (key, value)
            for key, value in parse_qsl(parsed.query, keep_blank_values=True)
            if key != name
        ]
        pairs.append((name, payload))
        return urlunsplit(parsed._replace(query=urlencode(pairs)))

    @staticmethod
    def _inject_path(url: str, name: str, payload: str) -> str:
        if not name.startswith("path_segment_"):
            return url
        try:
            index = int(name.rsplit("_", 1)[-1])
        except ValueError:
            return url
        parsed = urlsplit(url)
        segments = parsed.path.split("/")
        if index <= 0 or index >= len(segments):
            return url
        segments[index] = quote(payload, safe="")
        return urlunsplit(parsed._replace(path="/".join(segments)))

    def _make_finding(
        self,
        *,
        url: str,
        parameter: Parameter,
        payload: Payload,
        rendered: str,
        context: str,
        poc: ProofOfConcept,
        response: httpx.Response | None,
        probe: str = "HTTP reflection",
    ) -> Finding:
        digest = hashlib.sha256(
            f"{url}|{parameter.name}|{parameter.location.value}|"
            f"{payload.payload_id}|{rendered}".encode("utf-8", "replace")
        ).hexdigest()[:16]
        evidence: dict[str, Any] = {
            "probe": probe,
            "poc_method": poc.method,
        }
        if response is not None:
            evidence["response_status"] = response.status_code
        if poc.data:
            evidence["poc_data"] = poc.data
        if poc.headers:
            evidence["poc_headers"] = poc.headers
        if poc.cookies:
            evidence["poc_cookies"] = poc.cookies

        return Finding(
            finding_id=f"find_{digest}",
            target_url=url,
            parameter=parameter,
            payload=payload,
            status=FindingStatus.POTENTIAL,
            context=context,
            proof_url=poc.url,
            rendered_payload=rendered,
            marker=self.marker,
            poc=poc,
            evidence=evidence,
        )
