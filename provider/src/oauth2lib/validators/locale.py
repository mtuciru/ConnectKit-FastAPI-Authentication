"""
Regex for URIs

Implementation for RFC5646 Tags for Identifying Languages

    Language-Tag  = langtag                 ; normal language tags
                    / privateuse            ; private use tag
                    / grandfathered         ; grandfathered tags

    langtag       = language
                    ["-" script]
                    ["-" region]
                    *("-" variant)
                    *("-" extension)
                    ["-" privateuse]

    language      = 2*3ALPHA                ; shortest ISO 639 code
                    ["-" extlang]           ; sometimes followed by
                                            ; extended language subtags
                    / 4ALPHA                ; or reserved for future use
                    / 5*8ALPHA              ; or registered language subtag

    extlang       = 3ALPHA                  ; selected ISO 639 codes
                    *2("-" 3ALPHA)          ; permanently reserved

    script        = 4ALPHA                  ; ISO 15924 code

    region        = 2ALPHA                  ; ISO 3166-1 code
                    / 3DIGIT                ; UN M.49 code

    variant       = 5*8alphanum             ; registered variants
                    / (DIGIT 3alphanum)

    extension     = singleton 1*("-" (2*8alphanum))

                                            ; Single alphanumerics
                                            ; "x" reserved for private use
    singleton     = DIGIT                   ; 0 - 9
                    / %x41-57               ; A - W
                    / %x59-5A               ; Y - Z
                    / %x61-77               ; a - w
                    / %x79-7A               ; y - z

    privateuse    = "x" 1*("-" (1*8alphanum))

    grandfathered = irregular               ; non-redundant tags registered
                    / regular               ; during the RFC 3066 era

    irregular     = "en-GB-oed"             ; irregular tags do not match
                    / "i-ami"               ; the 'langtag' production and
                    / "i-bnn"               ; would not otherwise be
                    / "i-default"           ; considered 'well-formed'
                    / "i-enochian"          ; These tags are all valid,
                    / "i-hak"               ; but most are deprecated
                    / "i-klingon"           ; in favor of more modern
                    / "i-lux"               ; subtags or subtag
                    / "i-mingo"             ; combination
                    / "i-navajo"
                    / "i-pwn"
                    / "i-tao"
                    / "i-tay"
                    / "i-tsu"
                    / "sgn-BE-FR"
                    / "sgn-BE-NL"
                    / "sgn-CH-DE"

    regular       = "art-lojban"            ; these tags match the 'langtag'
                    / "cel-gaulish"         ; production, but their subtags
                    / "no-bok"              ; are not extended language
                    / "no-nyn"              ; or variant subtags: their meaning
                    / "zh-guoyu"            ; is defined by their registration
                    / "zh-hakka"            ; and all of these are deprecated
                    / "zh-min"              ; in favor of a more modern
                    / "zh-min-nan"          ; subtag or sequence of subtags
                    / "zh-xiang"

    alphanum      = (ALPHA / DIGIT)     ; letters and numbers
"""

import re

__all__ = ["language_tag_compiled", "is_language_tag", "parse_language_tags"]

## -*- charset -*-

# DIGIT = %x30-39
DIGIT = r"[0-9]"

# ALPHA = %x41-5A / %x61-7A
ALPHA = r"[A-Za-z]"

# alphanum = (ALPHA / DIGIT)
alphanum = rf"[A-Za-z0-9]"

## -*- Private use -*-

# privateuse = "x" 1*("-" (1*8alphanum))
privateuse = rf"(?: x (?: - {alphanum}{{1,8}} )+ )"

## -*- Lang Tag -*-

# extlang = 3ALPHA *2("-" 3ALPHA)
extlang = rf"(?: {ALPHA}{{3}} (?: - {ALPHA}{{3}} ){{0,2}} )"

# language      = 2*3ALPHA ["-" extlang] / 4ALPHA / 5*8ALPHA
language = rf"(?: {ALPHA}{{2,3}} (?: - {extlang} )? | {ALPHA}{{4}} | {ALPHA}{{5,8}} )"

# script = 4ALPHA
script = rf"(?: {ALPHA}{{4}} )"

# region = 2ALPHA / 3DIGIT
region = rf"(?: {ALPHA}{{2}} | {DIGIT}{{3}} )"

# variant = 5*8alphanum / (DIGIT 3alphanum)
variant = rf"(?: {alphanum}{{5,8}} | {DIGIT} {alphanum}{{3}} )"

# singleton = DIGIT / %x41-57 / %x59-5A / %x61-77 / %x79-7A
singleton = rf"[A-WY-Za-wy-z0-9]"

# extension = singleton 1*("-" (2*8alphanum))
extension = rf"(?: {singleton} (?: - {alphanum}{{2,8}} )+ )"

# langtag = language ["-" script] ["-" region] *("-" variant) *("-" extension) ["-" privateuse]
langtag = rf"(?: {language} (?: - {script} )? (?: - {region} )? (?: - {variant} )* (?: - {extension} )* (?: - {privateuse} )? )"

## -*- grandfathered -*-

# irregular = "en-GB-oed" / "i-ami" / "i-bnn" / "i-default" / "i-enochian" / "i-hak" / "i-klingon" / "i-lux" / "i-mingo"
#             / "i-navajo" / "i-pwn" / "i-tao" / "i-tay" / "i-tsu" / "sgn-BE-FR" / "sgn-BE-NL" / "sgn-CH-DE"
irregular = (rf"(?: en-GB-oed | i-ami | i-bnn | i-default | i-enochian | i-hak | i-klingon | i-lux | i-mingo | "
             rf"i-navajo | i-pwn | i-tao | i-tay | i-tsu | sgn-BE-FR | sgn-BE-NL | sgn-CH-DE )")

# regular = "art-lojban" / "cel-gaulish" / "no-bok" / "no-nyn" / "zh-guoyu" / "zh-hakka" / "zh-min" / "zh-min-nan"
#           / "zh-xiang"
regular = rf"(?: art-lojban | cel-gaulish | no-bok | no-nyn | zh-guoyu | zh-hakka | zh-min | zh-min-nan | zh-xiang )"

# grandfathered = irregular / regular
grandfathered = rf"(?: {irregular} | {regular} )"

## -*- Language Tag -*-

# Language-Tag  = langtag / privateuse / grandfathered
language_tag = rf"(?: {langtag} | {privateuse} | {grandfathered} )"

## -*- patterns & functions -*-

language_tag_compiled = re.compile(language_tag, re.VERBOSE)


def is_language_tag(language_tag_value: str) -> bool:
    """
    Check that *uri* string contains one single valid URI (as RFC3986)
    """
    return language_tag_compiled.fullmatch(language_tag_value) is not None


def parse_language_tags(language_tags: str) -> list[str]:
    language_tags = language_tags.encode().decode("ASCII", "ignore")
    seen = set()

    def seen_filter(lang_tag: str) -> bool:
        lang_tag = lang_tag.lower()
        if lang_tag in seen:
            return False
        seen.add(lang_tag)
        return True

    all_valid_values = language_tag_compiled.findall(language_tags)
    return list(filter(seen_filter, all_valid_values))
