# Launch plan: first real users in 3 weeks

**Who it's for:** people shipping apps built with Lovable, Bolt, Cursor or v0 on Supabase, Firebase or Next.js. Mostly non-security people who are scared of being the next "vibe-coded app leaked its users' data" post.

**Why they'll try it:** it's free, it's one command, and the output tells them exactly what's wrong in plain English.

**Goal for week 3:** 25 repos running the GitHub Action, 300 npm downloads, and at least 5 people saying it found something real.

## What the pre-launch scan showed

Before launch, ShipWarden was run on 11 public repos:
- 5 popular, well-maintained starter templates (Vercel, Supabase, Firebase)
- 6 recent public Lovable projects

- The maintained templates came back clean, apart from a Firebase codelab's rules marked "for demo purposes only" and some outdated `getSession()` examples.
- **2 of the 6 Lovable projects had tables that anyone, or any logged-in user, could modify** through `using (true)` policies. That's a small sample, but it's the story.

## Week 1: ship it

1. Create a public GitHub repo named `shipwarden` and push this code. Tag `v0.1.0` and also tag `v0`, so `@v0` keeps working.
2. Run `npm publish`. The name `shipwarden` was free when checked.
3. List it on GitHub Marketplace from the repo's Releases page. `action.yml` already has the branding.
4. Record a 30-second screen capture: `npx shipwarden` on the demo app, then the PR comment.
5. Post the launch, leading with the problem rather than the tool:
   - r/lovable, r/Supabase, r/nextjs, r/vibecoding, r/SideProject, r/webdev
   - Lovable, Bolt and Supabase Discords, in their showcase channels
   - X/Bluesky, tagging the posts with the demo GIF
   - Show HN: "ShipWarden – free security check for AI-built Supabase/Firebase apps"
   - Title idea: *"I scanned public Lovable apps for the mistakes that leak user data. Here's a free one-command check."*

## Week 2: do things that don't scale

- Offer free "scan my repo" checks in those communities. People send a public repo link, you run it and reply privately with the report. Every report gives you a testimonial or a false positive to fix.
- **Only scan and report on repos whose owners asked.** Don't open unsolicited issues or PRs on strangers' repos, and never publish names of vulnerable apps. Use aggregate numbers only.
- Fix every false positive within 24 hours and say so publicly. Trust is the product.

## Week 3: make it sticky

- Add the feature people ask for most. The likely candidate is a **live check**: given a Supabase URL plus anon key, try reading each table and report what's actually exposed. This catches dashboard-made tables the repo scan can't see.
- Write one post on the most common mistake you saw, with the fix. Posts like that keep bringing in search traffic.
- Track: Marketplace installs, npm weekly downloads, stars, and how many PR comments lead to a fix commit.

## Later (only if people use it)

Hosted dashboard, scheduled live checks, Slack alerts, and a team plan. Keep the CLI and Action free forever; that's the distribution.
