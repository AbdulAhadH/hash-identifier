# Hash Identifier

Python command line tool that takes a hash and determines what type of hash it is. 

## What it does

You give it a hash and it prints the possible hash types. Each result shows how confident the guess is (high, medium or low) and a short note on why.

## How it works

It checks things in this order:

1. **Prefix:** If the hash starts with a known prefix (like `$6$` for sha512crypt or `$2b$` for bcrypt), it returns that type right away with **high** confidence.
2. **Hex length:** If there was no prefix match, it checks that the hash is hex and that its length is one I know about (32, 40, 64 or 128). It returns every type with that length with **medium** confidence. For example, a 32 character hash could be MD5 or NTLM, so both are returned because length alone can't tell them apart.
3. **Nothing matched:** It returns **Unknown** with **low** confidence.

## Concepts used

- `dataclass` (with `frozen=True` and `slots=True`) for the `HashCandidate` class
- `Literal` to limit the confidence to a few exact values
- A list of tuples for the prefix rules and a dictionary for the hex length rules
- A `try` / `except` to check if a value is hex
- A list comprehension to build the results
- `sys.argv` to read the hash typed in the terminal

## How to run



```
python3 hash_identifier.py <hash>
```

If the hash has `$` signs in it, wrap it in single quotes so the terminal doesn't mess with it:

```
python3 hash_identifier.py '$6$somesalt$abcdef'
```

If you run it without a hash it prints a usage message.

## Example output

```
$ python3 hash_identifier.py '$6$somesalt$abcdef'
sha512crypt          [high]  matched prefix $6$

$ python3 hash_identifier.py 5d41402abc4b2a76b9719d911017c592
MD5                  [medium]  32 hex chars
NTLM                 [medium]  32 hex chars

$ python3 hash_identifier.py hello
Unknown              [low]  no rule matched
```

## Limitations

- It only knows the prefixes and lengths in `PREFIX_RULES` and `HEX_LENGTH_RULES`, so anything else comes back as Unknown (like `$5$` hashes or a 50 character hex string).

