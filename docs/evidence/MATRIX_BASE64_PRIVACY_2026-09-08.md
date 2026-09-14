# Matrix publisher: public Base64 is not an absolute path

CI run `34235956140` at source `028c44c886fe959c9081604aff4d1a214d673b9c`
failed in the PowerShell 7 publisher contract with
`MCACE_MATRIX_PUBLISH_ABSOLUTE_PATH_REJECTED|supervisor-trust-root`.
The dependent build failed closed, before its build work.

The privacy scanner applied a leading-slash filesystem rule to every JSON string.
RSA public modulus and signature Base64 can legitimately begin with `/`. The
contract generates a random RSA key, making this a nondeterministic false
rejection. A deterministic 256-byte public-byte fixture starting with 0xff
reproduced the rejection using the unchanged production validator.

The fix treats only exact top-level `modulus_base64` and `exponent_base64` in
the supervisor trust root, and `signature_base64` in its receipt, as public
cryptographic bytes. Encoding must be canonical Base64 without whitespace;
decoded lengths are bounded. Existing exact schema, key pinning, RSA verification,
and receipt binding checks remain mandatory. Ordinary paths, nested impersonation,
wrong document roles, malformed Base64 and secret fields are still rejected.
This does not mint or approve any release authority or real receipt.

Verification:

- Old validator: deterministic slash-prefixed public modulus rejected.
- Focused validator regression: four positive and seven negative cases passed
  on PowerShell 7 and Windows PowerShell 5.1.
- Complete publisher regression: PowerShell 7.6.5 passed, including all 48
  existing negative cases and force-idempotence checks.
- Complete publisher regression also passed on Windows PowerShell
  5.1.26100.9168, with the same 48 negative cases and force-idempotence checks.

Work was isolated in `D:/Projects/MCAce-matrix-base64-fix` while the source-bound
runtime matrix continued unchanged in `D:/Projects/MCAce`. The new focused test
is called by the existing publisher regression, so both CI PowerShell lanes
exercise it automatically.
