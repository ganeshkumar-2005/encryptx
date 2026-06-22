from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.helpers import make_web_request

class APIScanner:
    def __init__(self, target: str, timeout: float = 5.0):
        self.target = target
        if not target.startswith(("http://", "https://")):
            self.url = f"https://{target}"
        else:
            self.url = target
        self.timeout = timeout
        
        # Common API routes to test
        self.api_routes = [
            "api", "api/v1", "api/v2", "swagger.json", "openapi.json",
            "api-docs", "graphql", "rest", "v1/api", "v2/api"
        ]

    def _test_route(self, route: str) -> dict:
        test_url = f"{self.url}/{route}" if not self.url.endswith('/') else f"{self.url}{route}"
        result = {
            "route": route,
            "url": test_url,
            "exists": False,
            "status_code": 0,
            "type": "REST"
        }
        try:
            res = make_web_request(test_url, timeout=self.timeout)
            if res.status_code in (200, 401, 403, 405):
                result["exists"] = True
                result["status_code"] = res.status_code
                if "graphql" in route:
                    result["type"] = "GraphQL"
                elif "json" in route or "swagger" in route or "openapi" in route:
                    result["type"] = "Swagger Spec"
        except Exception:
            pass
        return result

    def scan(self, progress_callback=None) -> dict:
        findings = []
        discovered_routes = []
        total = len(self.api_routes)
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self._test_route, route): route for route in self.api_routes}
            
            for index, future in enumerate(as_completed(futures)):
                res = future.result()
                if res["exists"]:
                    discovered_routes.append(res)
                if progress_callback:
                    progress_callback(index + 1, total)

        for r in discovered_routes:
            # 1. API endpoint exposed
            findings.append({
                "module": "API Security Scanner",
                "target": r["url"],
                "severity": "INFO",
                "title": f"Exposed API Route Detected: /{r['route']}",
                "description": f"The application hosts an API route or specification format at /{r['route']}.",
                "evidence": f"URL: {r['url']}\nHTTP Code: {r['status_code']}\nType: {r['type']}",
                "remediation": "Verify that all endpoints on this route strictly enforce authentication and authorization scopes."
            })
            
            # 2. Check for Swagger API Specification file leakage
            if r["type"] == "Swagger Spec" and r["status_code"] == 200:
                findings.append({
                    "module": "API Security Scanner",
                    "target": r["url"],
                    "severity": "LOW",
                    "title": "API Specification Exposed",
                    "description": "API description documents (Swagger / OpenAPI specifications) are publicly accessible, giving potential attackers details on API methods, parameters, and payloads.",
                    "evidence": f"Specification exposed at: {r['url']}",
                    "remediation": "Restrict access to API specs in production environments. Shield swagger-ui pages behind authentication."
                })

            # 3. Check for GraphQL Introspection enabled
            if r["type"] == "GraphQL" and r["status_code"] == 200:
                # Send introspective probe query
                introspection_query = {"query": "{__schema{types{name}}}"}
                try:
                    res_intro = make_web_request(
                        r["url"], method="POST",
                        json_data=introspection_query,
                        headers={"Content-Type": "application/json"},
                        timeout=self.timeout
                    )
                    if "__schema" in res_intro.text:
                        findings.append({
                            "module": "API Security Scanner",
                            "target": r["url"],
                            "severity": "MEDIUM",
                            "title": "GraphQL Introspection Enabled",
                            "description": "GraphQL introspection queries are enabled. This allows any user to inspect schema details, types, arguments, and fields.",
                            "evidence": f"Introspection payload returned valid schema definitions.",
                            "remediation": "Disable GraphQL schema introspection in production deployment config."
                        })
                except Exception:
                    pass

        return {
            "target": self.url,
            "routes": discovered_routes,
            "findings": findings
        }
Class = APIScanner
