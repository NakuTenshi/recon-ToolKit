# Intigriti Program Summary Skill

## Purpose

When the user provides an Intigriti program URL, extract the important program information and create a concise Markdown summary file.

## Input

An Intigriti program URL, such as:

`https://app.intigriti.com/programs/<program-name>`

## Output

Create one Markdown file that includes:

* Program name
* Public or private status
* Program overview
* Scope
* Bounty or reward information
* Allowed testing
* Forbidden testing
* Rules
* Safe harbor or legal notes
* Important researcher notes
* Suggested recon priorities

## Extraction Rules

Summarize only the useful parts for a bug bounty hunter.

Focus on:

* In-scope assets
* Out-of-scope assets
* Bounty ranges or reward levels
* Rate limits or testing restrictions
* Authentication targets
* APIs
* GraphQL
* Mobile apps
* Admin panels
* Partner portals
* Special disclosure requirements
* Important exceptions or prohibitions

Do not copy long policy text verbatim. Compress aggressively and keep the result practical.

## File Format

Save the result as a Markdown file named like:

`reports/<program-name>.md`

## Markdown Structure

Use this structure:

```markdown
# Program Name

## Program Overview
- Platform: Intigriti
- Status:
- Reward available:
- Last updated:

## Bounty
- Low:
- Medium:
- High:
- Critical:

## Scope
### In Scope
- ...

### Out of Scope
- ...

## Rules
- ...

## Safe Harbor
- ...

## Researcher Notes
- ...

## Suggested Recon
- Domains:
- Interesting surfaces:
- Priority:
```

## Behavior

* If the URL belongs to an Intigriti program, summarize that program only.
* If important details are missing, say so clearly.
* Keep the report short, clear, and practical.
* Prefer bullet points over paragraphs.

