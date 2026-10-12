from dataclasses import dataclass
from typing import Literal #only thes exact values will be allowed

Confidence = Literal["High", "Medium", "Low"]

@dataclass(frozen=True, slots = True) #values cannot be changed, new random fields cannot later be added
class HashCandidate:
    name: str
    confidence: Confidence
    note: str

PREFIX_RULES: list[tuple[str,str]]= [ #List of defined prefixes and their corresponding hash types
    ("$2a$", "bcrypt"),
    ("$2b$", "bcrypt"),
    ("$2y$", "bcrypt"),
    ("$6$", "sha512crypt"),
    ("$1$", "md5crypt"),
    ("{SSHA}", "Salted SHA-1 (LDAP)"),
]


#Mapping the hex length of a hash to the possible hash types that can have that length
HEX_LENGTH_RULES: dict[int, list[str]] = {
    32: ["MD5", "NTLM"],
    40: ["SHA-1"],
    64: ["SHA-256"],
    128: ["SHA-512"],
}

#Checks the prefix first, then length, and finally returns a list of possible hash types

#If hex  return true, else return false
def is_hex(value: str) -> bool:
    try:
        int(value, 16)
        return True
    except ValueError:
        return False

def identify(raw: str) -> list[HashCandidate]:
    value = raw.strip()

    for prefix, name in PREFIX_RULES:
        if value.startswith(prefix):
            return [HashCandidate(name, "high", f"matched prefix {prefix}")]

    if is_hex(value) and len(value) in HEX_LENGTH_RULES:
        names = HEX_LENGTH_RULES[len(value)]
        return [
            HashCandidate(name, "medium", f"{len(value)} hex chars")
            for name in names
        ]

    return [HashCandidate("Unknown", "low", "no rule matched")]


import sys


def main() -> None:
    if len(sys.argv) < 2: #If ran without providing hash
        print("usage: python hash_identifier.py <hash>")
        return
    for candidate in identify(sys.argv[1]):
        print(f"{candidate.name:<20} [{candidate.confidence}]  {candidate.note}")


if __name__ == "__main__":
    main()