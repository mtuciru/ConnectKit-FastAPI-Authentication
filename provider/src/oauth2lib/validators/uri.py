"""
Regex for URIs

Implementation for RFC3986 Uniform Resource Identifier (URI): Generic Syntax

    URI           = scheme ":" hier-part [ "?" query ] [ "#" fragment ]

    hier-part     = "//" authority path-abempty
                 / path-absolute
                 / path-rootless
                 / path-empty

    URI-reference = URI / relative-ref

    absolute-URI  = scheme ":" hier-part [ "?" query ]

    relative-ref  = relative-part [ "?" query ] [ "#" fragment ]

    relative-part = "//" authority path-abempty
                 / path-absolute
                 / path-noscheme
                 / path-empty

    scheme        = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )

    authority     = [ userinfo "@" ] host [ ":" port ]
    userinfo      = *( unreserved / pct-encoded / sub-delims / ":" )
    host          = IP-literal / IPv4address / reg-name
    port          = *DIGIT

    IP-literal    = "[" ( IPv6address / IPvFuture  ) "]"

    IPvFuture     = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )

    IPv6address   =                            6( h16 ":" ) ls32
                 /                       "::" 5( h16 ":" ) ls32
                 / [               h16 ] "::" 4( h16 ":" ) ls32
                 / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
                 / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
                 / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
                 / [ *4( h16 ":" ) h16 ] "::"              ls32
                 / [ *5( h16 ":" ) h16 ] "::"              h16
                 / [ *6( h16 ":" ) h16 ] "::"

    h16           = 1*4HEXDIG
    ls32          = ( h16 ":" h16 ) / IPv4address
    IPv4address   = dec-octet "." dec-octet "." dec-octet "." dec-octet
    dec-octet     = DIGIT                 ; 0-9
                 / %x31-39 DIGIT         ; 10-99
                 / "1" 2DIGIT            ; 100-199
                 / "2" %x30-34 DIGIT     ; 200-249
                 / "25" %x30-35          ; 250-255

    reg-name      = *( unreserved / pct-encoded / sub-delims )

    path          = path-abempty    ; begins with "/" or is empty
                 / path-absolute   ; begins with "/" but not "//"
                 / path-noscheme   ; begins with a non-colon segment
                 / path-rootless   ; begins with a segment
                 / path-empty      ; zero characters

    path-abempty  = *( "/" segment )
    path-absolute = "/" [ segment-nz *( "/" segment ) ]
    path-noscheme = segment-nz-nc *( "/" segment )
    path-rootless = segment-nz *( "/" segment )
    path-empty    = 0<pchar>

    segment       = *pchar
    segment-nz    = 1*pchar
    segment-nz-nc = 1*( unreserved / pct-encoded / sub-delims / "@" )
                 ; non-zero-length segment without any colon ":"

    pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"

    query         = *( pchar / "/" / "?" )

    fragment      = *( pchar / "/" / "?" )

    pct-encoded   = "%" HEXDIG HEXDIG

    unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
    reserved      = gen-delims / sub-delims
    gen-delims    = ":" / "/" / "?" / "#" / "[" / "]" / "@"
    sub-delims    = "!" / "$" / "&" / "'" / "(" / ")"
                 / "*" / "+" / "," / ";" / "="
"""
import re

__all__ = ["URI_compiled", "relative_ref_compiled", "absolute_URI_compiled",
           "is_uri", "is_reference", "is_uri_reference", "is_absolute_uri", "is_scheme"]

## -*- charset -*-

# DIGIT = %x30-39
DIGIT = r"[0-9]"

# ALPHA = %x41-5A / %x61-7A
ALPHA = r"[A-Za-z]"

# HEXDIG = %x30-39 / %x41-46 / %x61-66
HEXDIG = r"[0-9A-Fa-f]"

# pct-encoded = "%" HEXDIG HEXDIG
pct_encoded = rf"(?: % {HEXDIG} {HEXDIG})"

# gen-delims = ":" / "/" / "?" / "#" / "[" / "]" / "@"
gen_delims = r"(?: : | / | \? | \# | \[ | \] | @ )"

# sub-delims = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
sub_delims = r"(?: ! | $ | & | ' | \( | \) | \* | \+ | , | ; | = )"

# unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
unreserved = rf"(?: {ALPHA} | {DIGIT} | \- | \. | _ | ~ )"

# reserved = gen-delims / sub-delims
reserved = rf"(?: {gen_delims} | {sub_delims} )"

## -*- scheme -*-

# scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
scheme = rf"(?P<scheme> {ALPHA} (?: {ALPHA} | {DIGIT} | \+ | \- | \. )* )"

## -*- IP & reg-name -*-

# dec-octet = DIGIT / %x31-39 DIGIT / "1" 2DIGIT / "2" %x30-34 DIGIT / "25" %x30-35
dec_octet = rf"(?: {DIGIT} | [1-9] {DIGIT} | 1 {DIGIT}{{2}} | 2 [0-4] {DIGIT} | 25 [0-5] )"

# IPv4address = dec-octet "." dec-octet "." dec-octet "." dec-octet
IPv4address = rf"(?: {dec_octet} \. {dec_octet} \. {dec_octet} \. {dec_octet} )"

# IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
IPvFuture = rf"(?: v {HEXDIG}+ \. (?: {unreserved} | {sub_delims} | : )+ )"

# h16 = 1*4HEXDIG
h16 = rf"(?: {HEXDIG}{{1,4}} )"

# ls32 = ( h16 ":" h16 ) / IPv4address
ls32 = rf"(?: {h16} : {h16} | {IPv4address} )"

# IPv6address = 6( h16 ":" ) ls32 /
#               "::" 5( h16 ":" ) ls32 /
#               [ h16 ] "::" 4( h16 ":" ) ls32 /
#               [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32 /
#               [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32 /
#               [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32 /
#               [ *4( h16 ":" ) h16 ] "::"              ls32 /
#               [ *5( h16 ":" ) h16 ] "::"              h16 /
#               [ *6( h16 ":" ) h16 ] "::"
IPv6address = (rf"(?: "
               rf"(?: {h16} : ){{6}} {ls32} | "
               rf":: (?: {h16} : ){{5}} {ls32} | "
               rf"{h16}? :: (?: {h16} : ){{4}} {ls32} | "
               rf"(?: (?: {h16} : ){{0,1}} {h16} )? :: (?: {h16} : ){{3}} {ls32} | "
               rf"(?: (?: {h16} : ){{0,2}} {h16} )? :: (?: {h16} : ){{2}} {ls32} | "
               rf"(?: (?: {h16} : ){{0,3}} {h16} )? :: {h16} : {ls32} | "
               rf"(?: (?: {h16} : ){{0,4}} {h16} )? :: {ls32} | "
               rf"(?: (?: {h16} : ){{0,5}} {h16} )? :: {h16} | "
               rf"(?: (?: {h16} : ){{0,6}} {h16} )? :: "
               rf")")

# IP-literal = "[" ( IPv6address / IPvFuture  ) "]"
IP_literal = rf"(?: \[ (?: {IPv6address} | {IPvFuture} ) \] )"

# reg-name = *( unreserved / pct-encoded / sub-delims )
reg_name = rf"(?: (?: {unreserved} | {pct_encoded} | {sub_delims} )* )"

## -*- authority -*-

# userinfo = *( unreserved / pct-encoded / sub-delims / ":" )
userinfo = rf"(?: (?: {unreserved} | {pct_encoded} | {sub_delims} | : )* )"

# host = IP-literal / IPv4address / reg-name
host = rf"(?: {IP_literal} | {IPv4address} | {reg_name} )"

# port = *DIGIT
port = rf"(?: {DIGIT}* )"

# authority = [ userinfo "@" ] host [ ":" port ]
authority = rf"(?P<authority> (?: {userinfo} @ )? {host} (?: : {port} )? )"

## -*- segment -*-

# pchar = unreserved / pct-encoded / sub-delims / ":" / "@"
pchar = rf"(?: {unreserved} | {pct_encoded} | {sub_delims} | : | @ )"

# segment = *pchar
segment = rf"(?: {pchar}* )"

# segment-nz = 1*pchar
segment_nz = rf"(?: {pchar}+ )"

# segment-nz-nc = 1*( unreserved / pct-encoded / sub-delims / "@" )
segment_nz_nc = rf"(?: (?: {unreserved} | {pct_encoded} | {sub_delims} | @ )+ )"

## -*- path -*-

# path-abempty = *( "/" segment )
path_abempty = rf"(?P<path> (?: / {segment} )* )"

# path-absolute = "/" [ segment-nz *( "/" segment ) ]
path_absolute = rf"(?: / (?: {segment_nz} (?: / {segment} )* )? )"

# path-noscheme = segment-nz-nc *( "/" segment )
path_noscheme = rf"(?: {segment_nz_nc} (?: / {segment} )* )"

# path-rootless = segment-nz *( "/" segment )
path_rootless = rf"(?: {segment_nz} (?: / {segment} )* )"

# path-empty = 0<pchar>
path_empty = rf"(?: {pchar}{{0}} )"

# path = path-abempty / path-absolute / path-noscheme / path-rootless / path-empty
# path = rf"(?: {path_abempty} | {path_absolute} | {path_noscheme} | {path_rootless} | {path_empty} )"

## -*- hier-part -*-

# Exclude some part of hier-part to give name to group
hier_part_path = rf"(?P<path_any> {path_absolute} | {path_rootless} | {path_empty} )"

# hier-part = "//" authority path-abempty / path-absolute / path-rootless / path-empty
hier_part = rf"(?: // {authority} {path_abempty} | {hier_part_path} )"

## -*- relative-part -*-

# Exclude some part of relative-part to give name to group
relative_part_path = rf"(?P<path_any> {path_absolute} | {path_noscheme} | {path_empty} )"

# relative-part = "//" authority path-abempty / path-absolute / path-noscheme / path-empty
relative_part = rf"(?: // {authority} {path_abempty} | {relative_part_path} )"

## -*- query -*-

# query = *( pchar / "/" / "?" )
query = rf"(?P<query> (?: {pchar} | / | \? )* )"

## -*- fragment -*-

# fragment = *( pchar / "/" / "?" )
fragment = rf"(?P<fragment> (?: {pchar} | / | \? )* )"

## -*- URI -*-

# relative-ref  = relative-part [ "?" query ] [ "#" fragment ]
relative_ref = rf"(?: {relative_part} (?: \? {query})? (?: \# {fragment})? )"

# URI = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
URI = rf"(?: {scheme} : {hier_part} (?: \? {query} )? (?: \# {fragment} )? )"

# absolute-URI  = scheme ":" hier-part [ "?" query ]
absolute_URI = rf"(?: {scheme} : {hier_part} (?: \? {query} )? )"

## -*- patterns & functions -*-

relative_ref_compiled = re.compile(relative_ref, re.VERBOSE)

URI_compiled = re.compile(URI, re.VERBOSE)

absolute_URI_compiled = re.compile(absolute_URI, re.VERBOSE)


def is_uri(uri: str) -> bool:
    """
    Check that *uri* string contains one single valid URI (as RFC3986)
    """
    return URI_compiled.fullmatch(uri) is not None


def is_reference(uri: str) -> bool:
    """
    Check that *uri* string contains one single valid reference (as RFC3986)
    """
    return relative_ref_compiled.fullmatch(uri) is not None


def is_uri_reference(uri: str) -> bool:
    """
    Check that *uri* string contains one single valid reference or one single valid URI (as RFC3986)
    """
    return is_uri(uri) or is_reference(uri)


def is_absolute_uri(uri: str) -> bool:
    """
    Check that *uri* string contains one single valid absolute URI (as RFC3986)
    """
    return absolute_URI_compiled.fullmatch(uri) is not None


def is_scheme(uri: str, target_scheme: str) -> bool:
    """
    Check that *uri* string contains one single valid URI (as RFC3986)
    and URI scheme equals *target_scheme*
    """
    m = URI_compiled.fullmatch(uri)
    if m is None:
        return False
    groups = m.groupdict()
    if "scheme" not in groups:
        return False
    if groups["scheme"].lower() != target_scheme.lower():
        return False
    return True
