# 1Password secret references — SAFE TO COMMIT (no secret values, only op:// paths).
# Edit the vault/item/field names to match your 1Password. Resolve at runtime with:
#   op run --env-file=.env.tpl -- <your command>
# or via ./op-run.sh, or automatically via direnv (see envrc.template).

FLEXSPRING_PARTNER_KEY=op://PenTest/Flexspring dev partner key/credential
COMPANY_A_TOKEN=op://PenTest/Company A/token
COMPANY_A_UUID=op://PenTest/Company A/uuid
COMPANY_B_TOKEN=op://PenTest/Company B/token
COMPANY_B_UUID=op://PenTest/Company B/uuid
