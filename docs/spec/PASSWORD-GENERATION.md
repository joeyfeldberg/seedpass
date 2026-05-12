# PASSWORD-GENERATION

Status: `seedpass-v1-draft`.

MVP passwords are ASCII-only.

## Fixed classes

```text
lowercase = "abcdefghijklmnopqrstuvwxyz"
uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
digits    = "0123456789"
symbols   = profile_snapshot.symbols exactly as written
```

Custom lowercase, uppercase, or digit classes are not supported in MVP.

## Profile validation

- `length` must be between 8 and 256 inclusive.
- Minimum class counts must be nonnegative integers.
- Sum of minimum counts must be `<= length`.
- Symbols must be ASCII printable and non-whitespace.
- Duplicate symbols are rejected.
- Symbols must not overlap lowercase, uppercase, or digits.
- If `min_symbols > 0`, symbols must be non-empty.
- The allowed union must be non-empty.

## Draw integer

Use rejection sampling over stream bytes:

```text
limit = floor(256 / n) * n
read byte b
if b >= limit, reject and read another byte
return b mod n
```

## Algorithm

1. Validate profile.
2. Draw required uppercase characters.
3. Draw required lowercase characters.
4. Draw required digit characters.
5. Draw required symbol characters.
6. Draw remaining characters from the union `lowercase || uppercase || digits || symbols`.
7. Deterministically shuffle using Fisher-Yates:

```text
for i from len(chars)-1 down to 1:
  j = draw_int(i + 1)
  swap(chars[i], chars[j])
```

## Vectors

See `tests/vectors/v1-draft-001.json`.
