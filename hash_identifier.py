from dataclasses import dataclass
from typing import Literal #only these exact values will be allowed

Confidence = Literal["High", "Medium", "Low"]

@dataclass(frozen=True, slots = True) #values cannot be changed, new random fields cannot later be added
class HashCandidate: #One possible guess at what the hash is, how sure we are, and why
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

#If hex, return true, else return false
def is_hex(value: str) -> bool:
    try:
        int(value, 16) #Tries to turn the value into a base 16 number, if it fails then it is not hex
        return True
    except ValueError:
        return False

def identify(raw: str) -> list[HashCandidate]:
    value = raw.strip()

    #Goes through the prefix rules in order, return stops the function as soon as one matches (high confidence)
    for prefix, name in PREFIX_RULES:
        if value.startswith(prefix):
            return [HashCandidate(name, "high", f"matched prefix {prefix}")]

    #No prefix matched so check the length, confidence is only medium because different hash types can share a length
    if is_hex(value) and len(value) in HEX_LENGTH_RULES:
        names = HEX_LENGTH_RULES[len(value)]
        #Makes one HashCandidate for every name in the list (ex. 32 gives both MD5 and NTLM)
        return [
            HashCandidate(name, "medium", f"{len(value)} hex chars")
            for name in names
        ]

    return [HashCandidate("Unknown", "low", "no rule matched")]


import sys


def main() -> None:
    if len(sys.argv) < 2: #If run without providing a hash
        print("usage: python hash_identifier.py <hash>")
        return
    #sys.argv is the list of what was typed in the terminal, [0] is the file name and [1] is the hash
    for candidate in identify(sys.argv[1]):
        #:<20 pads the name to 20 characters so the columns line up
        print(f"{candidate.name:<20} [{candidate.confidence}]  {candidate.note}")


if __name__ == "__main__": #Only runs main() when this file is run directly, not when imported
    main()