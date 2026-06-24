import urllib.parse
from bs4 import BeautifulSoup
from utils.helpers import make_web_request

class Crawler:
    def __init__(self, target_url: str, timeout: float = 5.0, make_request_fn=None):
        self.target_url = target_url
        if not target_url.startswith(("http://", "https://")):
            self.root_url = f"https://{target_url}"
        else:
            self.root_url = target_url
        self.timeout = timeout
        self.make_request_fn = make_request_fn or make_web_request

    def _is_same_host(self, url: str) -> bool:
        try:
            parsed_url = urllib.parse.urlparse(url)
            parsed_root = urllib.parse.urlparse(self.root_url)
            url_host = parsed_url.hostname or ""
            root_host = parsed_root.hostname or ""
            return url_host.lower() == root_host.lower()
        except Exception:
            return False

    def crawl(self) -> dict:
        visited_pages = set()
        urls_with_params = set()
        form_targets = []
        seen_forms = set()  # To deduplicate forms: (action, method, tuple(fields))

        queue = [self.root_url]

        while queue and len(visited_pages) < 30:
            current_url = queue.pop(0)

            # Clean/normalize current_url by stripping fragment
            try:
                parsed_current = urllib.parse.urlparse(current_url)
                clean_current = urllib.parse.urlunparse((
                    parsed_current.scheme,
                    parsed_current.netloc,
                    parsed_current.path,
                    parsed_current.params,
                    parsed_current.query,
                    ''
                ))
            except Exception:
                continue

            if clean_current in visited_pages:
                continue

            # Check same host before visiting
            if not self._is_same_host(clean_current):
                continue

            try:
                response = self.make_request_fn(clean_current, timeout=self.timeout)
                visited_pages.add(clean_current)
                if not response or response.status_code != 200:
                    continue

                html_content = response.text
                soup = BeautifulSoup(html_content, "html.parser")

                # 1. Collect and parse all HTML forms
                for form in soup.find_all("form"):
                    action = form.get("action", "")
                    # Resolve relative actions
                    resolved_action = urllib.parse.urljoin(clean_current, action)
                    
                    # Remove fragment from resolved_action
                    try:
                        parsed_action = urllib.parse.urlparse(resolved_action)
                        clean_action = urllib.parse.urlunparse((
                            parsed_action.scheme,
                            parsed_action.netloc,
                            parsed_action.path,
                            parsed_action.params,
                            parsed_action.query,
                            ''
                        ))
                    except Exception:
                        clean_action = resolved_action

                    # Keep forms within the same host
                    if not self._is_same_host(clean_action):
                        continue

                    method = form.get("method", "GET").upper()
                    if method not in ("GET", "POST"):
                        method = "GET"

                    # Collect fields: inputs, textareas, selects
                    fields = []
                    for input_tag in form.find_all(["input", "textarea", "select"]):
                        name = input_tag.get("name")
                        if name:
                            fields.append(name)
                    # Deduplicate fields while preserving order
                    fields = list(dict.fromkeys(fields))

                    form_key = (clean_action, method, tuple(fields))
                    if form_key not in seen_forms:
                        seen_forms.add(form_key)
                        form_targets.append({
                            "action": clean_action,
                            "method": method,
                            "fields": fields
                        })

                # 2. Extract internal links from <a> tags to crawl
                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"].strip()
                    # Skip empty or javascript links
                    if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                        continue

                    resolved_url = urllib.parse.urljoin(clean_current, href)
                    
                    try:
                        parsed_url = urllib.parse.urlparse(resolved_url)
                        # We only follow http and https schemes
                        if parsed_url.scheme not in ("http", "https"):
                            continue

                        clean_url = urllib.parse.urlunparse((
                            parsed_url.scheme,
                            parsed_url.netloc,
                            parsed_url.path,
                            parsed_url.params,
                            parsed_url.query,
                            ''
                        ))
                    except Exception:
                        continue

                    if self._is_same_host(clean_url):
                        # If has parameters, add to urls_with_params
                        if parsed_url.query:
                            urls_with_params.add(clean_url)
                        
                        # Add to queue if not already visited or in queue
                        if clean_url not in visited_pages and clean_url not in queue:
                            queue.append(clean_url)

            except Exception:
                # Add to visited pages so we don't retry endlessly in case of exception
                visited_pages.add(clean_current)

        # Also, check if root url itself has query parameters
        try:
            root_parsed = urllib.parse.urlparse(self.root_url)
            if root_parsed.query:
                # Strip fragment
                clean_root = urllib.parse.urlunparse((
                    root_parsed.scheme,
                    root_parsed.netloc,
                    root_parsed.path,
                    root_parsed.params,
                    root_parsed.query,
                    ''
                ))
                urls_with_params.add(clean_root)
        except Exception:
            pass

        return {
            "urls_with_params": sorted(list(urls_with_params)),
            "form_targets": form_targets,
            "pages_visited": len(visited_pages)
        }
