from playwright.sync_api import sync_playwright
import os

class BrowserManager:
    def __init__(self, headless=False, storage_state=None):
        self.headless = headless
        self.storage_state = storage_state
        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None
    
    def start(self):
        self.playwright = sync_playwright().start()
        opts = {}
        if self.storage_state and os.path.exists(self.storage_state):
            opts["storage_state"] = self.storage_state
        self.browser = self.playwright.chromium.launch(headless=self.headless)
        self.context = self.browser.new_context(**opts)
        self.page = self.context.new_page()
        return self.page
    
    def stop(self):
        if self.browser: self.browser.close()
        if self.playwright: self.playwright.stop()
    
    def get_page(self): return self.page
    def get_context(self): return self.context
