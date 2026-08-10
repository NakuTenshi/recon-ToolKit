# Recon Suggest Domain for Hunt

## Description
This skill visits each live domain one by one, analyzes the website's features, size, and user interaction capabilities, then suggests which domains are worth hunting on and why. Prioritizes based on application complexity and feature richness.

## Trigger
When user says `/recon-suggest-domain-for-hunt` followed by a filename containing live domains, e.g.:
/recon-suggest-domain-for-hunt live_httpx.txt
/recon-suggest-domain-for-hunt live_domains.txt
/recon-suggest-domain-for-hunt targets.txt

## Instructions

### Step 1: Parse Input
- Extract the filename from user's command
- Verify the file exists and contains domains/URLs (one per line)
- If file doesn't exist, tell user and stop

### Step 2: Visit Each Domain
For each domain/URL in the file, use the web_fetch or browser capability to:
- Open and load the main page
- Observe the structure, content, and functionality visible

### Step 3: Analyze Features & User Interaction
For each website, evaluate and note:

Feature Categories to Look For:

1. Authentication/Authorization
   - Login/Register/Signup forms
   - Password reset functionality
   - OAuth or social login options
   - Multi-user roles (admin, user, moderator)
   - Account settings/profile pages

2. User Input & Data Handling
   - Search functionality (especially advanced search)
   - File upload capabilities (images, documents, etc.)
   - Comment/review systems
   - Contact forms / feedback forms
   - Newsletter subscription
   - Custom calculators or tools accepting input

3. Transactional Features
   - Shopping cart / e-commerce
   - Payment processing / checkout
   - Subscription plans / billing
   - Booking/reservation systems
   - Order tracking

4. Interactive & Dynamic Features
   - Real-time chat or messaging
   - WebSocket connections
   - API endpoints visible or documented
   - Webhooks or integrations
   - Dynamic content loading (AJAX, infinite scroll)
   - Interactive dashboards or user panels
   - Notification systems

5. Scale & Complexity Indicators
   - Number of pages/sections
   - JavaScript framework in use (React, Angular, Vue, etc.)
   - Multiple subdomains or services
   - Admin panels or CMS (WordPress, Drupal, custom)
   - Third-party integrations
   - Mobile app references or PWA features

### Step 4: Scoring & Recommendation
Rate each domain on a scale of 1-10 for "Hunt Worthiness" based on:

| Factor | Weight |
|--------|--------|
| Feature Richness (number of interactive features) | 40% |
| Complexity (dynamic functionality, JS heavy) | 25% |
| Data Sensitivity (handles user data, payments, auth) | 20% |
| Attack Surface Size (more endpoints/inputs = more surface) | 15% |

Scoring Guidelines:
- 8-10 (High Priority): Rich features, auth, file upload, payments, complex JS. Spend serious time here.
- 5-7 (Medium Priority): Some interactive features, login present, moderate complexity. Worth checking.
- 1-4 (Low Priority): Static or mostly informational, minimal input, simple structure. Low chance of critical bugs.

### Step 5: Output Format
Present findings as a structured report:

## Domain Hunt Analysis

### High Priority Targets (Score 8-10)
| Domain | Score | Key Features | Why Worth Hunting |
|--------|-------|--------------|-------------------|
| example.com | 9/10 | Login, File Upload, Payments | Full e-commerce with file handling - XSS, IDOR, file upload vulns likely |

### Medium Priority Targets (Score 5-7)
| Domain | Score | Key Features | Why Worth Hunting |
|--------|-------|--------------|-------------------|
| blog.example.com | 6/10 | Search, Comments, Login | User input via comments + auth = stored XSS, CSRF potential |

### Low Priority Targets (Score 1-4)
| Domain | Score | Key Features | Why Worth Hunting |
|--------|-------|--------------|-------------------|
| static.example.com | 2/10 | Static pages only | No user interaction, minimal attack surface |

### Summary
- Total Domains Analyzed: X
- High Priority: Y
- Medium Priority: Z
- Low Priority: W

### Step 6: Actionable Advice
For each high-priority domain, add 1-2 specific suggestions:
- "Check file upload for unrestricted types - potential RCE"
- "Test password reset flow for token prediction"
- "Look for IDOR in /user/profile endpoint"
- "Map JavaScript files for hidden API endpoints"

### Important Notes
- Visit ALL domains, don't skip any
- If a domain is down or times out, note it and move on
- Focus on VISIBLE features - don't try to brute force or scan
- Provide SPECIFIC reasons, not generic statements
- The scoring helps prioritize time investment