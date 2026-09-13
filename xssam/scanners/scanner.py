import asyncio
from typing import List, Dict, Any, Tuple, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from xssam.core.models import Finding, FindingStatus, Parameter, Payload, ParameterLocation
from xssam.utils.http import AsyncHttpClient
from xssam.payloads.corpus import PayloadCorpus, ContextAnalyzer
from xssam.payloads.encodings import PayloadMutator

class ReflectionChecker:
    def check(self, response_text: str, payload_text: str) -> bool:
        return payload_text in response_text

class XSSScanner:
    def __init__(self, client: AsyncHttpClient):
        self.client = client
        self.corpus = PayloadCorpus()
        self.analyzer = ContextAnalyzer()
        self.ref_checker = ReflectionChecker()
        self.mutator = PayloadMutator()

    async def scan_parameter(self, url: str, parameter: Parameter) -> List[Finding]:
        findings = []

        # 1. Context Analysis (Canary test)
        canary_payload = self.analyzer.canary
        canary_resp = await self._perform_injection(url, parameter, canary_payload)
        if not canary_resp:
            return []

        context = self.analyzer.analyze(canary_resp.text)

        # 2. Payload Testing
        payloads = self.corpus.get_payloads(context)
        for payload in payloads:
            # NEXT-LEVEL: Test multiple mutations of the same payload
            mutations = self.mutator.mutate(payload.text)

            for mutated_text in mutations:
                res = await self._perform_injection(url, parameter, mutated_text)
                if not res:
                    continue

                if self.ref_checker.check(res.text, mutated_text):
                    proof_url = self._generate_proof_url(url, parameter, mutated_text)

                    findings.append(Finding(
                        finding_id=f"find_{payload.payload_id}_{parameter.name}_{hash(mutated_text)}",
                        target_url=url,
                        parameter=parameter,
                        payload=payload, # Store original payload metadata
                        status=FindingStatus.REFLECTED,
                        context=context,
                        proof_url=proof_url,
                        severity="Medium",
                        confidence="Low"
                    ))
                    # If one mutation of a payload works, we can stop testing other mutations of the same payload
                    break

        return findings

    async def _perform_injection(self, url: str, parameter: Parameter, payload: str) -> Optional[Any]:
        method = "GET"
        request_url = url
        data = None
        headers = {}
        cookies = {}

        if parameter.location == ParameterLocation.QUERY:
            request_url = self._inject_query(url, parameter.name, payload)
        elif parameter.location == ParameterLocation.PATH:
            request_url = self._inject_path(url, parameter.name, payload)
        elif parameter.location == ParameterLocation.FORM or parameter.location == ParameterLocation.BODY:
            method = "POST"
            data = {parameter.name: payload}
        elif parameter.location == ParameterLocation.HEADER:
            headers[parameter.name] = payload
        elif parameter.location == ParameterLocation.COOKIE:
            cookies[parameter.name] = payload
        elif parameter.location == ParameterLocation.FRAGMENT:
            request_url = f"{url}#{payload}"

        return await self.client.request(
            method=method,
            url=request_url,
            data=data,
            headers=headers,
            cookies=cookies
        )

    def _inject_query(self, url: str, name: str, payload: str) -> str:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        qs[name] = [payload]
        new_query = urlencode(qs, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _inject_path(self, url: str, name: str, payload: str) -> str:
        if "path_segment_" in name:
            try:
                idx = int(name.split("_")[-1])
                parsed = urlparse(url)
                segments = parsed.path.split("/")
                if idx < len(segments):
                    segments[idx] = payload
                    new_path = "/".join(segments)
                    return urlunparse(parsed._replace(path=new_path))
            except ValueError:
                pass
        return url

    def _generate_proof_url(self, url: str, parameter: Parameter, payload: str) -> str:
        if parameter.location == ParameterLocation.QUERY:
            return self._inject_query(url, parameter.name, payload)
        if parameter.location == ParameterLocation.PATH:
            return self._inject_path(url, parameter.name, payload)
        return f"{url} [Location: {parameter.location.value}, Param: {parameter.name}]"
