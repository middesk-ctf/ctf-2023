import os; os.system('playwright install')

from playwright.sync_api import sync_playwright
import time

while True:
  with sync_playwright() as p:
    browser = p.chromium.launch(headless=False)
    page = browser.new_page()
    page.goto("http://localhost:3000")

    # Sign in
    page.click('#login-button')
    time.sleep(2)
    page.locator('#username').fill('admin')
    page.locator('#password').fill(os.getenv('ADMIN_PASSWORD') or 'admin')
    page.click('#login-button')
    time.sleep(1)

    # Go to the view files (admin only)
    page.goto("http://localhost:3000/files")
    time.sleep(1)

    # TODO: Click on the first shared file
    # page.click(...)

    page.close()
    browser.close()
