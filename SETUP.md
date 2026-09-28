# GOGO AI Keys Panel Setup

## Local HTML

Your existing local HTML can stay:

```html
<!doctype html>
<script src="https://rzhtesfikvykdnmrqwjs.supabase.co/functions/v1/keys-panel"></script>
```

Do not change unrelated links.

## GitHub Actions secrets

In the repository settings, add these Actions secrets:

```
SUPABASE_ACCESS_TOKEN
SUPABASE_PROJECT_REF
MONGO_URI
ADMIN_PASSWORD
```

Use this project ref:

```
rzhtesfikvykdnmrqwjs
```

The MongoDB URI must point at the ai_assistant database/cluster. The administrator password is supplied only as a deployment/runtime secret.

## Automatic deployment

Pushing changes under:

```
supabase/functions/keys-panel/
```

runs:

```
GitHub Actions -> Supabase CLI -> keys-panel Edge Function
```

The permanent endpoint is:

```
https://rzhtesfikvykdnmrqwjs.supabase.co/functions/v1/keys-panel
```

## MongoDB collections

The function uses:

```
ai_assistant.api_keys
ai_assistant.audit_logs
```

Keys, devices, status, expiry, remarks, notes and audit history remain in MongoDB.
