# signup-assist

Fills the six sign-up forms for you in a real browser window and stops only
when a page needs a human: a CAPTCHA, a code sent to your phone or email, or
your card. It never reads card details from anywhere.

```bash
cd lab/setup/signup-assist
npm run setup                         # once: Playwright + Chromium
cp profile.example.json profile.json  # your name, phone, company, domain, a password for the admin account
npm run microsoft                     # creates the tenant
npm run azure
npm run okta
npm run aws
npm run servicenow
```

At the prompt: **Enter** clicks Next, `fill` fills again, `click Text` clicks a
button, `done` stops and prints what to copy into `../handback.env`.
`node assist.mjs okta --scan` lists the fields on the first page without
filling anything (headless), useful when a site changes its form.
