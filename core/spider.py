import re

class Spider:
    def __init__(self, page, base_url):
        self.page = page
        self.base_url = base_url.rstrip('/')
    
    def crawl(self):
        urls = set()
        try:
            links = self.page.locator("a").evaluate_all("(els) => els.map(el => el.href)")
            for link in links:
                if link.startswith(self.base_url) and "logout" not in link.lower():
                    urls.add(link)
            
            scripts = self.page.locator("script").evaluate_all("(els) => els.map(el => el.textContent)")
            for script in scripts:
                found = re.findall(r'["\x27](\/api\/[a-zA-Z0-9_\/-]+)["\x27]', script)
                for api in found:
                    urls.add(f"{self.base_url}{api}")
        except: pass
        return list(urls)
