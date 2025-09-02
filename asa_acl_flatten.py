#!/usr/bin/env python3
"""
Flatten Cisco ASA ACLs from an Excel 'one-liner' dump into a single Excel:
columns: acl, action, protocol, src, src_port, dst, dst_port, raw

Assumptions
- Input Excel has one column containing ASA config one-liners
- Supports: object network/service, object-group network/service, access-list ... extended ...
- Resolves object/object-group references in ACLs for source/destination and services
- Ports: eq, range, lt, gt, neq (emits textual operator for non-eq/range)
- Addresses: host, subnet (keeps 'ip mask'), range (keeps 'start-end'), any/any4/any6

Limitations (quick to extend)
- Does not evaluate 'interface' network names or dynamic objects
- Does not parse service “object” protocols beyond tcp/udp/icmp/ip; unknown protocols are kept as-is
- No time-range, inactive, remarks logic; NAT/route ignored here on purpose
"""
import argparse, os, sys, re
from itertools import product
from datetime import datetime

try:
    import pandas as pd
except Exception as e:
    print("[FATAL] pandas not installed:", e)
    sys.exit(1)

# ---------- Helpers ----------
def clean(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip())

def as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]

def uniq(seq):
    seen=set(); out=[]
    for x in seq:
        if x not in seen:
            out.append(x); seen.add(x)
    return out

# ---------- Parsers for object blocks ----------
RE_OBJ_NET   = re.compile(r"^object\s+network\s+(\S+)\s*$", re.I)
RE_OBJ_SVC   = re.compile(r"^object\s+service\s+(\S+)\s*$", re.I)
RE_GRP_NET   = re.compile(r"^object-group\s+network\s+(\S+)\s*$", re.I)
RE_GRP_SVC   = re.compile(r"^object-group\s+service\s+(\S+)\s*$", re.I)

RE_NET_MEMBER= re.compile(r"^(host\s+\S+|subnet\s+\S+\s+\S+|range\s+\S+\s+\S+)\s*$", re.I)
RE_NET_OBJREF= re.compile(r"^network-object\s+(object\s+\S+|host\s+\S+|(\S+)(?:\s+\S+){0,2}.*?)\s*$", re.I)
RE_SVC_MEMBER= re.compile(r"^service-object\s+(.+)$", re.I)
RE_SVC_PROTO = re.compile(r"^(tcp|udp|icmp|ip)\b(.*)$", re.I)

# ACL (generic “rest” is parsed later)
RE_ACL = re.compile(r"^access-list\s+(\S+)\s+extended\s+(permit|deny)\s+(\S+)\s+(.+)$", re.I)

def parse_net_literal(txt:str):
    """Return normalized address string(s)."""
    t = txt.lower().strip()
    if t.startswith("host "):
        return [txt.split()[1]]
    if t.startswith("subnet "):
        # keep 'ip mask' together
        _, ip, mask, *rest = txt.split()
        return [f"{ip} {mask}"]
    if t.startswith("range "):
        _, a, b, *rest = txt.split()
        return [f"{a}-{b}"]
    if t in ("any","any4","any6"):
        return [t]
    return [txt]  # fallback

def parse_port_clause(tokens):
    """
    tokens for eq/lt/gt/neq/range PORT(S)
    Returns (op, value) textual; for eq single port, for range 'a-b'
    """
    if not tokens:
        return ("", "")
    t0 = tokens[0].lower()
    if t0 == "eq" and len(tokens)>=2:
        return ("eq", tokens[1])
    if t0 == "range" and len(tokens)>=3:
        return ("range", f"{tokens[1]}-{tokens[2]}")
    if t0 in ("lt","gt","neq") and len(tokens)>=2:
        return (t0, tokens[1])
    # fallback: join
    return ("", " ".join(tokens))

def parse_service_object(line:str):
    """
    service-object tcp eq 80
    service-object udp range 1000 2000
    service-object tcp destination eq 443 (ASA allows destination keyword inside)
    """
    m = RE_SVC_MEMBER.match(line)
    if not m: 
        return []
    rest = clean(m.group(1))
    # allow optional 'destination' keyword
    rest = re.sub(r"\bdestination\s+", "", rest, flags=re.I)
    m2 = RE_SVC_PROTO.match(rest)
    if not m2:
        return []
    proto = m2.group(1).lower()
    toks = clean(m2.group(2)).split()
    op,val = parse_port_clause(toks)
    # For icmp/ip, ports don't apply
    if proto in ("icmp","ip"):
        return [(proto, "", "")]
    return [(proto, op, val)]

# ---------- Main ----------
def main():
    ap = argparse.ArgumentParser(description="Flatten ASA ACLs from Excel into one Excel with resolved aliases.")
    ap.add_argument("--in", dest="infile", required=True, help="Input Excel (.xlsx/.xls)")
    ap.add_argument("--sheet", default=None, help="Sheet name (default: first)")
    ap.add_argument("--col", default=None, help="Column name with ASA lines (default: first col)")
    ap.add_argument("--out", dest="outfile", default=None, help="Output .xlsx (default: asa_acl_flatten_YYYYMMDD-HHMMSS.xlsx)")
    ap.add_argument("--debug", action="store_true", help="Verbose stderr logging")
    args = ap.parse_args()

    # Load excel
    if not os.path.exists(args.infile):
        print(f"[FATAL] Input not found: {args.infile}")
        sys.exit(2)

    xls = pd.ExcelFile(args.infile)
    sheet = args.sheet or xls.sheet_names[0]
    if sheet not in xls.sheet_names:
        print(f"[FATAL] Sheet '{sheet}' not found. Available: {xls.sheet_names}")
        sys.exit(3)
    df = xls.parse(sheet)
    col = args.col or (df.columns[0] if len(df.columns) else None)
    if col not in df.columns:
        print(f"[FATAL] Column '{args.col}' not found. Columns: {list(df.columns)}")
        sys.exit(4)

    lines = [clean(str(x)) for x in df[col].fillna("").tolist() if str(x).strip()]

    # Collect definitions
    obj_net   = {}  # name -> list[str literal members]
    obj_svc   = {}  # name -> list[(proto,op,val)]
    grp_net   = {}  # name -> list of either literals or 'object NAME'
    grp_svc   = {}  # name -> list[(proto,op,val)] or 'object NAME'
    acls      = []  # list of (acl, action, proto (from 'ip/tcp/udp/icmp' position), rest, raw)

    cur = None  # (type, name)

    def add_net_member(name, txt):
        # txt may be literal or "object X" or network-object host/subnet/range
        if txt.lower().startswith("object "):
            # object reference inside group
            grp_net.setdefault(name, [])
            grp_net[name].append(txt)
        else:
            vals = parse_net_literal(txt)
            obj_net.setdefault(name, [])
            obj_net[name].extend(vals)

    def add_svc_member(name, line):
        parts = parse_service_object(line)
        if parts:
            obj_svc.setdefault(name, [])
            obj_svc[name].extend(parts)

    for ln in lines:
        # Block starts
        m = RE_OBJ_NET.match(ln)
        if m:
            cur=("obj_net", m.group(1)); obj_net.setdefault(cur[1], [])
            continue
        m = RE_OBJ_SVC.match(ln)
        if m:
            cur=("obj_svc", m.group(1)); obj_svc.setdefault(cur[1], [])
            continue
        m = RE_GRP_NET.match(ln)
        if m:
            cur=("grp_net", m.group(1)); grp_net.setdefault(cur[1], [])
            continue
        m = RE_GRP_SVC.match(ln)
        if m:
            cur=("grp_svc", m.group(1)); grp_svc.setdefault(cur[1], [])
            continue

        if cur:
            t, name = cur
            if t=="obj_net":
                if RE_NET_MEMBER.match(ln):
                    obj_net[name].extend(parse_net_literal(ln))
                    continue
            elif t=="obj_svc":
                if RE_SVC_MEMBER.match(ln):
                    add_svc_member(name, ln)
                    continue
            elif t=="grp_net":
                mg = RE_NET_OBJREF.match(ln)
                if mg:
                    payload = clean(mg.group(1))
                    # Normalize literals to same format as parse_net_literal
                    if payload.lower().startswith("object "):
                        grp_net[name].append(payload)  # will resolve later
                    else:
                        grp_net[name].extend(parse_net_literal(payload))
                    continue
            elif t=="grp_svc":
                if RE_SVC_MEMBER.match(ln):
                    # can be "service-object object NAME" OR literal tcp/udp...
                    if re.match(r"^service-object\s+object\s+(\S+)$", ln, re.I):
                        grp_svc[name].append(clean(ln))  # keep as reference
                    else:
                        grp_svc.setdefault(name, [])
                        grp_svc[name].extend(parse_service_object(ln))
                    continue
            # If the line clearly leaves block context
            if RE_ACL.match(ln) or ln.lower().startswith("object ") or ln.lower().startswith("object-group "):
                cur=None

        # ACLs
        ma = RE_ACL.match(ln)
        if ma:
            acls.append((ma.group(1), ma.group(2).lower(), ma.group(3).lower(), clean(ma.group(4)), ln))

    # ---------- Resolution ----------
    # Build resolvers for network and service names (object + object-group)
    def resolve_net_name(name:str, _depth=0):
        if _depth>10:  # guard
            return []
        if name in obj_net:
            return uniq(obj_net[name])
        if name in grp_net:
            out=[]
            for item in grp_net[name]:
                if isinstance(item, str) and item.lower().startswith("object "):
                    ref = item.split()[1]
                    out.extend(resolve_net_name(ref, _depth+1))
                else:
                    out.extend(as_list(item))
            return uniq(out)
        return []

    def resolve_svc_name(name:str, _depth=0):
        if _depth>10:
            return []
        if name in obj_svc:
            return uniq(obj_svc[name])
        if name in grp_svc:
            out=[]
            for it in grp_svc[name]:
                if isinstance(it, str) and it.lower().startswith("service-object object "):
                    ref = it.split()[2]
                    out.extend(resolve_svc_name(ref, _depth+1))
                else:
                    # tuple (proto,op,val)
                    out.extend(as_list(it))
            return uniq(out)
        return []

    # ---------- Parse ACL “rest” to extract src/dst + ports and object refs ----------
    # Handles common shapes:
    #  <proto> <srcPart> <dstPart>
    # Where srcPart/dstPart may contain:
    #   any | any4 | any6 | host A.B.C.D | object NAME | object-group NAME | <ip> <mask>
    #   (for tcp/udp) optional: (eq|lt|gt|neq|range ...) attached to src or dst, most often dst
    #
    def split_src_dst(rest:str):
        toks = rest.split()
        # Consume source
        src_tokens=[]
        i=0
        def take_addr(i):
            if i>=len(toks): return i, []
            t=toks[i].lower()
            if t in ("any","any4","any6"):
                return i+1, [toks[i]]
            if t=="host" and i+1<len(toks):
                return i+2, ["host", toks[i+1]]
            if t=="object" and i+1<len(toks):
                return i+2, ["object", toks[i+1]]
            if t=="object-group" and i+1<len(toks):
                return i+2, ["object-group", toks[i+1]]
            # ip + mask
            if i+1 < len(toks) and re.match(r"^\d+\.\d+\.\d+\.\d+$", toks[i]) and re.match(r"^\d+\.\d+\.\d+\.\d+$", toks[i+1]):
                return i+2, [toks[i], toks[i+1]]
            return i+1, [toks[i]]  # fallback single
        i, src_tokens = take_addr(i)
        # Optional source port clause (tcp/udp)
        i_src_after = i
        if i < len(toks) and toks[i].lower() in ("eq","lt","gt","neq","range"):
            # source port clause
            if toks[i].lower()=="range" and i+2<len(toks):
                src_port_tokens = toks[i:i+3]; i+=3
            elif i+1<len(toks):
                src_port_tokens = toks[i:i+2]; i+=2
            else:
                src_port_tokens = [toks[i]]; i+=1
        else:
            src_port_tokens = []

        # Destination part
        i, dst_tokens = take_addr(i)
        # Optional destination port clause
        if i < len(toks) and toks[i].lower() in ("eq","lt","gt","neq","range"):
            if toks[i].lower()=="range" and i+2<len(toks):
                dst_port_tokens = toks[i:i+3]; i+=3
            elif i+1<len(toks):
                dst_port_tokens = toks[i:i+2]; i+=2
            else:
                dst_port_tokens = [toks[i]]; i+=1
        else:
            dst_port_tokens = []

        return src_tokens, src_port_tokens, dst_tokens, dst_port_tokens

    def resolve_addr(tokens):
        # tokens like: ["any"], ["host",IP], ["object",NAME], ["object-group",NAME], [IP, MASK]
        if not tokens:
            return [""]
        t0 = tokens[0].lower()
        if t0 in ("any","any4","any6"):
            return [t0]
        if t0=="host" and len(tokens)>=2:
            return [tokens[1]]
        if t0=="object" and len(tokens)>=2:
            return resolve_net_name(tokens[1]) or [f"object:{tokens[1]}"]
        if t0=="object-group" and len(tokens)>=2:
            return resolve_net_name(tokens[1]) or [f"object-group:{tokens[1]}"]
        if len(tokens)==2 and re.match(r"^\d+\.\d+\.\d+\.\d+$", tokens[0]) and re.match(r"^\d+\.\d+\.\d+\.\d+$", tokens[1]):
            return [f"{tokens[0]} {tokens[1]}"]
        # fallback
        return [" ".join(tokens)]

    def resolve_ports(tokens, default_proto):
        if not tokens:
            return ("", "")
        op,val = parse_port_clause(tokens)
        # leave textual
        return (op, val)

    # ---------- Build flat rows ----------
    flat_rows=[]
    for acl_name, action, proto_hint, rest, raw in acls:
        src_t, srcp_t, dst_t, dstp_t = split_src_dst(rest)

        # Services can appear as 'object'/'object-group' immediately after protocol position
        # Example: "tcp object-group SRV-GRP object DMZ-SRV eq 80"
        # We detect when src_t or dst_t is actually 'object' referencing a *service* by trying service resolver
        # but only if tokens are exactly ['object', NAME] or ['object-group', NAME]
        svc_parts = []
        def maybe_svc(tokens):
            if len(tokens)==2 and tokens[0].lower() in ("object","object-group"):
                name=tokens[1]
                parts = resolve_svc_name(name)
                if parts:
                    return parts
            return []

        # Service resolution precedence:
        # 1) if src/dst tokens resolve as service objects, we will use those ports;
        # 2) else, use explicit eq/range tokens parsed on src/dst;
        # 3) else, fall back to proto_hint with empty ports.
        resolved_services = maybe_svc(src_t) or maybe_svc(dst_t)

        if resolved_services:
            svc_list = resolved_services
        else:
            # Use proto hint; ports from src/dst port tokens if any
            if proto_hint.lower() in ("tcp","udp"):
                op_s,val_s = resolve_ports(srcp_t, proto_hint)
                op_d,val_d = resolve_ports(dstp_t, proto_hint)
                # If both empty, create one row with empty ports
                if op_s or val_s or op_d or val_d:
                    svc_list = [(proto_hint, op_d or op_s, (val_d or val_s))]
                else:
                    svc_list = [(proto_hint, "", "")]
            elif proto_hint.lower() in ("icmp","ip"):
                svc_list = [(proto_hint.lower(), "", "")]
            else:
                svc_list = [(proto_hint.lower(), "", "")]

        src_addrs = resolve_addr(src_t)
        dst_addrs = resolve_addr(dst_t)

        for saddr, daddr, svc in product(src_addrs, dst_addrs, svc_list):
            proto, port_op, port_val = svc
            # Determine whether port belongs to destination (most ASA rules) — keep in dst_port
            src_port = ""
            dst_port = ""
            if proto in ("tcp","udp"):
                # If we had explicit dst port tokens, use them; else put the service tuple under dst_port
                if dstp_t:
                    op_d, val_d = resolve_ports(dstp_t, proto)
                    dst_port = f"{op_d} {val_d}".strip()
                elif srcp_t:
                    op_s, val_s = resolve_ports(srcp_t, proto)
                    src_port = f"{op_s} {val_s}".strip()
                elif port_op or port_val:
                    dst_port = f"{port_op} {port_val}".strip()

            flat_rows.append({
                "acl": acl_name,
                "action": action,
                "protocol": proto,
                "src": saddr,
                "src_port": src_port,
                "dst": daddr,
                "dst_port": dst_port,
                "raw": raw
            })

    # ---------- Write Excel ----------
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = args.outfile or f"asa_acl_flatten_{ts}.xlsx"
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)

    if not flat_rows:
        # still write empty with headers to prove pipeline works
        flat_rows = [{"acl":"","action":"","protocol":"","src":"","src_port":"","dst":"","dst_port":"","raw":""}]

    out_df = pd.DataFrame(flat_rows, columns=["acl","action","protocol","src","src_port","dst","dst_port","raw"])
    # Sort for readability
    out_df = out_df.sort_values(["acl","action","protocol","src","dst","dst_port"], ignore_index=True)
    with pd.ExcelWriter(out, engine="openpyxl") as xw:
        out_df.to_excel(xw, index=False, sheet_name="ACLs_flat")
    print(f"[OK] Wrote: {out}  (rows: {len(out_df)})")

if __name__ == "__main__":
    main()
