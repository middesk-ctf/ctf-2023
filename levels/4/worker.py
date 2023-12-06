import os
import time
from urllib.parse import urljoin

from playwright.sync_api import sync_playwright

BASE_URL = "http://localhost:3000"

while True:
    time.sleep(5)
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True
        )  # Set this to False when testing locally
        page = browser.new_page()
        page.goto(BASE_URL)
        time.sleep(2)

        # Sign in
        page.click("#login-button")
        time.sleep(1)
        page.locator("#username").fill("admin")
        time.sleep(1)
        page.locator("#password").fill(os.getenv("ADMIN_PASSWORD") or "ctfPassword1")
        time.sleep(1)
        page.click("#login-button")
        time.sleep(1)

        # Go to the view files (admin only)
        page.goto("http://localhost:3000/files")
        time.sleep(1)

        # Get all elements matching the selector
        # These are the links to the "Files Shared With You"
        elements = page.query_selector_all("#received-wrapper li a")

        # Extract any href attributes. It's okay if there are none.
        hrefs = [element.get_attribute("href") for element in elements]
        for href in hrefs:
            joined_url = urljoin(BASE_URL, href)
            print(f"navigating to {href} -> {joined_url}")
            page.goto(joined_url)
            time.sleep(2)

        time.sleep(5)

        page.close()
        browser.close()
