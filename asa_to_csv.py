#!/usr/bin/env python3
"""
asa_to_csv.py
-------------
Parse a Cisco ASA configuration and export a CSV of ACL entries with resolved
source/destination networks and service ports.

Coverage (common cases):
- object network NAME { host A.B.C.D | subnet A.B.C.D MASK | range A.B.C.D A.B.C.D }
- object-group network NAME with nested:
    - network-object { host IP | A.B.C.D MASK | range A.B.C.D A.B.C.D }
    - group-object OTHER_GROUP
- object-group service NAME [tcp|udp|icmp|ip] with:
    - service-object { tcp|udp [source/destination ...] [eq|range|gt|lt|neq] ... }
    - port-object { eq|range|gt|lt|neq } ...
    - group-object OTHER_GROUP
- (basic) object service NAME (interpreted like a 1-line service-object)
- access-list <NAME> extended (permit|deny) <proto>
    <src-spec> <dst-spec> [service/port spec OR object-group <SERVICE_GROUP>]
  where src/dst spec can be: any | host IP | object NAME | object-group NAME | IP MASK

Outputs CSV columns:
acl, action, protocol, src, src_port, dst, dst_port, raw

Limitations:
- Does not parse time-range, remarks, user-identity, ASA9.x "object network NAME subnet ... nat ..." combos, etc.
- NAT rules are not expanded here (focus is ACL matrix).

Usage:
    python asa_to_csv.py input.conf output.csv
"""

import sys
import re
import csv
import ipaddress
from collections import defaultdict, deque

# ----------------- Helpers -----------------

def mask_to_prefix(mask_str):
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask_str}").prefixlen
    except Exception:
        return None

def to_cidr(ip, mask):
    pfx = mask_to_prefix(mask)
    if pfx is None:
        return f"{ip} {mask}"
    return f"{ip}/{pfx}"

def normalize_host(ip):
    try:
        return str(ipaddress.ip_network(ip + "/32", strict=False))
    except Exception:
        return ip

def normalize_subnet(ip, mask):
    try:
        net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
        return str(net)
    except Exception:
        return to_cidr(ip, mask)

def normalize_range(start_ip, end_ip):
    # keep as start-end (ranges are rare in ACLs; ASA allows them in groups)
    return f"{start_ip}-{end_ip}"

def flatten(lst):
    out = []
    for x in lst:
        if isinstance(x, (list, tuple)):
            out.extend(x)
        else:
            out.append(x)
    return out

# ----------------- Data Stores -----------------

# network objects: name -> list of strings (CIDR or range)
net_objects = defaultdict(list)         # "object network X"
net_groups = defaultdict(list)          # "object-group network X" (members: ('net', value) or ('group', name))

# service objects/groups
serv_objects = defaultdict(list)        # "object service X" -> list of ('proto','dst_port_expr')
serv_groups = defaultdict(list)         # "object-group service X" -> list like above OR ('group', name)

# ----------------- Parsing Pass -----------------

def parse_file(lines):
    cur_section = None
    cur_name = None
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("!"):
            continue

        # Section starts
        m = re.match(r"^object\s+network\s+(\S+)", line, re.I)
        if m:
            cur_section = ('net_object', m.group(1))
            cur_name = m.group(1)
            continue

        m = re.match(r"^object-group\s+network\s+(.+)$", line, re.I)
        if m:
            name = m.group(1).strip()
            cur_section = ('net_group', name)
            cur_name = name
            continue

        m = re.match(r"^object-group\s+service\s+(.+)$", line, re.I)
        if m:
            name = m.group(1).strip()
            cur_section = ('serv_group', name)
            cur_name = name
            continue

        m = re.match(r"^object\s+service\s+(\S+)", line, re.I)
        if m:
            cur_section = ('serv_object', m.group(1))
            cur_name = m.group(1)
            continue

        # Inside sections
        if cur_section:
            kind, name = cur_section

            if kind == 'net_object':
                # host X | subnet A M | range A B
                mh = re.match(r"^host\s+(\d+\.\d+\.\d+\.\d+)$", line, re.I)
                if mh:
                    net_objects[name].append(normalize_host(mh.group(1)))
                    continue
                ms = re.match(r"^subnet\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)$", line, re.I)
                if ms:
                    net_objects[name].append(normalize_subnet(ms.group(1), ms.group(2)))
                    continue
                mr = re.match(r"^range\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)$", line, re.I)
                if mr:
                    net_objects[name].append(normalize_range(mr.group(1), mr.group(2)))
                    continue
                # ignore others
                continue

            if kind == 'net_group':
                # network-object host X | network-object A M | range | group-object NAME
                mnoh = re.match(r"^network-object\s+host\s+(\d+\.\d+\.\d+\.\d+)$", line, re.I)
                if mnoh:
                    net_groups[name].append(('net', normalize_host(mnoh.group(1))))
                    continue

                mno = re.match(r"^network-object\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)$", line, re.I)
                if mno:
                    net_groups[name].append(('net', normalize_subnet(mno.group(1), mno.group(2))))
                    continue

                mnr = re.match(r"^network-object\s+range\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)$", line, re.I)
                if mnr:
                    net_groups[name].append(('net', normalize_range(mnr.group(1), mnr.group(2))))
                    continue

                mg = re.match(r"^group-object\s+(.+)$", line, re.I)
                if mg:
                    net_groups[name].append(('group', mg.group(1).strip()))
                    continue
                continue

            if kind == 'serv_group' or kind == 'serv_object':
                target = serv_groups if kind == 'serv_group' else serv_objects

                # service-object tcp|udp [destination] (eq|range|gt|lt|neq) N [M]
                mso = re.match(r"^service-object\s+(tcp|udp|icmp|ip)(.*)$", line, re.I)
                if mso:
                    proto = mso.group(1).lower()
                    rest = mso.group(2).strip()
                    # try to extract a destination port expression
                    # look for keywords around 'destination' or at end
                    port_expr = parse_port_expr(rest)
                    target[name].append((proto, port_expr or '*'))
                    continue

                mpo = re.match(r"^port-object\s+(.*)$", line, re.I)
                if mpo:
                    # port-object belongs to last declared proto at group header, but ASA allows header like:
                    # object-group service NAME tcp
                    # We'll try to infer from group name header line (not tracked) -> fallback to tcp/udp unknown ('*')
                    port_expr = parse_port_expr(mpo.group(1))
                    target[name].append(('*', port_expr or '*'))
                    continue

                mg = re.match(r"^group-object\s+(.+)$", line, re.I)
                if mg:
                    target[name].append(('group', mg.group(1).strip()))
                    continue

                # object service can be one-liner like: service tcp destination eq 443
                ms = re.match(r"^service\s+(tcp|udp|icmp|ip)\s+(.*)$", line, re.I)
                if ms:
                    proto = ms.group(1).lower()
                    port_expr = parse_port_expr(ms.group(2))
                    target[name].append((proto, port_expr or '*'))
                    continue

                continue

        # Outside any section: we don't handle here (ACLs parsed later)
        pass

# Port expression parser
def parse_port_expr(rest: str):
    # look for destination first
    # patterns like: "destination eq 443", "destination range 1000 2000"
    m = re.search(r"\bdestination\s+(eq|range|gt|lt|neq)\s+(\S+)(?:\s+(\S+))?", rest, re.I)
    if m:
        op = m.group(1).lower()
        a = m.group(2)
        b = m.group(3)
        return op_to_range(op, a, b)

    # fall back to a bare "eq 443" etc.
    m = re.search(r"\b(eq|range|gt|lt|neq)\s+(\S+)(?:\s+(\S+))?", rest, re.I)
    if m:
        op = m.group(1).lower()
        a = m.group(2)
        b = m.group(3)
        return op_to_range(op, a, b)

    return None

def op_to_range(op, a, b=None):
    # ASA names like www->80 allowed; keep as-is if not int
    if op == 'eq':
        return a
    if op == 'range' and b:
        return f"{a}-{b}"
    if op in ('gt','lt','neq'):
        return f"{op} {a}"
    return '*'

# ----------------- Resolution -----------------

def resolve_net(name, seen=None):
    """Return list of network strings for an object or group name."""
    if seen is None: seen = set()
    if name in seen:
        return []
    seen.add(name)
    out = []
    if name in net_objects:
        out.extend(net_objects[name])
    if name in net_groups:
        for kind, val in net_groups[name]:
            if kind == 'net':
                out.append(val)
            elif kind == 'group':
                out.extend(resolve_net(val, seen))
    return list(dict.fromkeys(out))  # dedupe, keep order

def resolve_service(name, seen=None):
    if seen is None: seen = set()
    if name in seen:
        return []
    seen.add(name)
    out = []
    if name in serv_objects:
        out.extend(serv_objects[name])
    if name in serv_groups:
        for item in serv_groups[name]:
            if isinstance(item, tuple) and len(item) == 2 and item[0] == 'group':
                out.extend(resolve_service(item[1], seen))
            elif isinstance(item, tuple) and len(item) == 2:
                out.append(item)  # (proto, port_expr)
    # normalize '*' proto
    norm = []
    for proto, port in out:
        if proto == '*':
            # duplicate for tcp/udp as common case
            norm.append(('tcp', port))
            norm.append(('udp', port))
        else:
            norm.append((proto, port))
    # dedupe
    seen_set = set()
    dedup = []
    for proto, port in norm:
        key = (proto, port)
        if key not in seen_set:
            dedup.append((proto, port))
            seen_set.add(key)
    return dedup

# ----------------- ACL Parsing -----------------

ACL_RE = re.compile(r"^access-list\s+(\S+)\s+extended\s+(permit|deny)\s+(\S+)\s+(.*)$", re.I)

def parse_addr_spec(tokens, i):
    """
    Parse an ASA address spec starting at tokens[i].
    Returns (list_of_networks, next_index).
    """
    if i >= len(tokens):
        return (['ANY'], i)
    tok = tokens[i].lower()

    if tok == 'any':
        return (['ANY'], i+1)

    if tok == 'host' and i+1 < len(tokens):
        return ([normalize_host(tokens[i+1])], i+2)

    if tok == 'object' and i+1 < len(tokens):
        name = tokens[i+1]
        nets = resolve_net(name)
        if nets:
            return (nets, i+2)
        else:
            # maybe it's an object service (rare in addr position) -> treat as ANY
            return (['OBJECT:'+name], i+2)

    if tok == 'object-group' and i+1 < len(tokens):
        name = tokens[i+1]
        nets = resolve_net(name)
        if nets:
            return (nets, i+2)
        else:
            return (['OBJGRP:'+name], i+2)

    # IP MASK
    if re.match(r"\d+\.\d+\.\d+\.\d+", tokens[i]) and i+1 < len(tokens) and re.match(r"\d+\.\d+\.\d+\.\d+", tokens[i+1]):
        return ([normalize_subnet(tokens[i], tokens[i+1])], i+2)

    # fallback: single token (unexpected)
    return ([tokens[i]], i+1)

def parse_port_after_dst(proto, tokens, i):
    """
    Parse port spec after destination in ACL:
    - eq 80 | range 1000 2000
    - object-group SERVICENAME
    Returns (list_of_port_exprs, next_index, protocol_override|None)
    """
    ports = []
    proto_override = None
    if i >= len(tokens):
        return (['*'], i, proto_override)

    tok = tokens[i].lower()
    if tok in ('eq','range','gt','lt','neq'):
        if tok == 'eq' and i+1 < len(tokens):
            ports = [tokens[i+1]]
            i += 2
        elif tok == 'range' and i+2 < len(tokens):
            ports = [f"{tokens[i+1]}-{tokens[i+2]}"]
            i += 3
        elif tok in ('gt','lt','neq') and i+1 < len(tokens):
            ports = [f"{tok} {tokens[i+1]}"]
            i += 2
        else:
            ports = ['*']
    elif tok == 'object-group' and i+1 < len(tokens):
        name = tokens[i+1]
        # resolve service group
        svc = resolve_service(name)
        # Collect ports for matching proto (or all)
        ports = []
        protos = set()
        for sp, pexpr in svc:
            ports.append(pexpr or '*')
            protos.add(sp.lower())
        # If svc defines a single specific protocol, we can override
        if len(protos) == 1:
            proto_override = list(protos)[0]
        i += 2
    else:
        ports = ['*']

    if not ports:
        ports = ['*']
    return (ports, i, proto_override)

def parse_acls(lines):
    rows = []
    for raw in lines:
        line = raw.strip()
        m = ACL_RE.match(line)
        if not m:
            continue
        acl, action, proto, rest = m.groups()
        proto = proto.lower()
        # Tokenize rest
        tokens = rest.split()
        # Source
        src_list, idx = parse_addr_spec(tokens, 0)
        # Destination
        dst_list, idx = parse_addr_spec(tokens, idx)
        # Ports (if tcp/udp) or via service group
        ports = ['*']
        proto_override = None
        if proto in ('tcp','udp','ip'):
            ports, idx, proto_override = parse_port_after_dst(proto, tokens, idx)
            if proto == 'ip' and proto_override:
                proto = proto_override
        elif proto == 'icmp':
            ports = ['*']  # ICMP types not parsed here

        # Expand cartesian product
        for s in src_list:
            for d in dst_list:
                for p in ports:
                    rows.append({
                        'acl': acl,
                        'action': action,
                        'protocol': proto_override or proto,
                        'src': s,
                        'src_port': '*',
                        'dst': d,
                        'dst_port': p,
                        'raw': line
                    })
    return rows

# ----------------- Main -----------------

def main():
    if len(sys.argv) < 3:
        print("Usage: python asa_to_csv.py input.conf output.csv")
        sys.exit(1)

    infile = sys.argv[1]
    outfile = sys.argv[2]

    with open(infile, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    # First pass: build object/group dictionaries
    parse_file(lines)

    # Second pass: ACLs
    rows = parse_acls(lines)

    # Write CSV
    fieldnames = ['acl','action','protocol','src','src_port','dst','dst_port','raw']
    with open(outfile, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)

    # Report basic stats
    print(f"Wrote {len(rows)} ACL rows to {outfile}")
    print(f"Network objects: {len(net_objects)} | groups: {len(net_groups)} | Service objects: {len(serv_objects)} | groups: {len(serv_groups)}")

if __name__ == "__main__":
    # local helper for parsing port expressions needs to be defined earlier
    pass  # replaced by definitions above

# Fix for the __main__ guard (since we've declared pass above)
if __name__ == "__main__":
    main()
