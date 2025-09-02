#!/usr/bin/env python3
import argparse, sys, re, json, os
from datetime import datetime

try:
    import pandas as pd
except Exception as e:
    print("[FATAL] pandas not installed:", e)
    sys.exit(1)

def debug(msg, enable):
    if enable:
        print(msg)

def main():
    ap = argparse.ArgumentParser(description="Parse ASA one-liners from an Excel file (single text column).")
    ap.add_argument("--in", dest="infile", required=True, help="Path to Excel file (.xlsx/.xls)")
    ap.add_argument("--sheet", dest="sheet", default=None, help="Sheet name (default: first sheet)")
    ap.add_argument("--col", dest="col", default=None, help="Column name with ASA lines (default: first column)")
    ap.add_argument("--outdir", dest="outdir", default="out", help="Output directory")
    ap.add_argument("--debug", action="store_true", help="Verbose logging")
    args = ap.parse_args()

    infile = args.infile
    outdir = args.outdir
    os.makedirs(outdir, exist_ok=True)

    # Timestamped prefix so you always know where outputs went.
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    prefix = os.path.join(outdir, f"asa_{stamp}")

    # Load Excel and sanity print
    if not os.path.exists(infile):
        print(f"[FATAL] Input file not found: {infile}")
        sys.exit(2)

    try:
        xls = pd.ExcelFile(infile)
    except Exception as e:
        print(f"[FATAL] Failed to open Excel: {e}")
        sys.exit(3)

    print(f"[INFO] Opened Excel: {infile}")
    print("[INFO] Sheets found:", xls.sheet_names)

    sheet_name = args.sheet or xls.sheet_names[0]
    if sheet_name not in xls.sheet_names:
        print(f"[FATAL] Sheet '{sheet_name}' not found. Available: {xls.sheet_names}")
        sys.exit(4)

    df = xls.parse(sheet_name)
    print(f"[INFO] Using sheet: {sheet_name} with {len(df)} rows")
    print("[INFO] Columns in sheet:", list(df.columns))

    col = args.col or (df.columns[0] if len(df.columns) else None)
    if col is None or col not in df.columns:
        print(f"[FATAL] Column '{args.col}' not found. Detected columns: {list(df.columns)}")
        sys.exit(5)

    # Clean input lines
    lines = (
        df[col]
        .astype(str)
        .str.strip()
        .replace({"nan": ""})
        .tolist()
    )
    # Remove empties
    lines = [ln for ln in lines if ln]
    print(f"[INFO] Non-empty input lines: {len(lines)}")

    # Write raw lines snapshot so you can confirm we read the file
    raw_csv = f"{prefix}_raw_lines.csv"
    pd.DataFrame({"line": lines}).to_csv(raw_csv, index=False)
    print(f"[INFO] Wrote raw snapshot: {raw_csv}")

    # Simple ASA patterns (expand as needed)
    re_obj_net   = re.compile(r"^object\s+network\s+(\S+)\s*$", re.IGNORECASE)
    re_obj_svc   = re.compile(r"^object\s+service\s+(\S+)\s*$", re.IGNORECASE)
    re_obj_grp   = re.compile(r"^object-group\s+network\s+(\S+)\s*$", re.IGNORECASE)
    re_svc_grp   = re.compile(r"^object-group\s+service\s+(\S+)", re.IGNORECASE)
    re_net_line  = re.compile(r"^(host\s+\S+|subnet\s+\S+\s+\S+|range\s+\S+\s+\S+)\s*$", re.IGNORECASE)
    re_svc_line  = re.compile(r"^(service-object\s+\S+(\s+\S+)*)\s*$", re.IGNORECASE)
    re_group_obj = re.compile(r"^(network-object\s+.*|service-object\s+.*)\s*$", re.IGNORECASE)
    re_acl       = re.compile(
        r"^access-list\s+(\S+)\s+extended\s+(permit|deny)\s+(\S+)\s+(.+)$",
        re.IGNORECASE
    )
    re_nat       = re.compile(r"^nat\s*\(.*\)\s+.*$", re.IGNORECASE)
    re_iface     = re.compile(r"^interface\s+.+$", re.IGNORECASE)

    # State machines to collect object/object-group members
    objects_net = {}        # name -> list of entries (host/subnet/range lines)
    objects_svc = {}        # name -> list of service-object lines
    groups_net  = {}        # name -> list of network-object lines
    groups_svc  = {}        # name -> list of service-object lines
    acls        = []        # dicts
    nats        = []
    ifaces      = []

    cur_block = None        # ("type", "name")
    def end_block():
        nonlocal cur_block
        cur_block = None

    for i, ln in enumerate(lines, 1):
        ln_stripped = ln.strip()
        # Detect new blocks
        m = re_obj_net.match(ln_stripped)
        if m:
            cur_block = ("obj_net", m.group(1))
            objects_net.setdefault(cur_block[1], [])
            debug(f"[DBG] #{i} start object network {cur_block[1]}", args.debug)
            continue

        m = re_obj_svc.match(ln_stripped)
        if m:
            cur_block = ("obj_svc", m.group(1))
            objects_svc.setdefault(cur_block[1], [])
            debug(f"[DBG] #{i} start object service {cur_block[1]}", args.debug)
            continue

        m = re_obj_grp.match(ln_stripped)
        if m:
            cur_block = ("grp_net", m.group(1))
            groups_net.setdefault(cur_block[1], [])
            debug(f"[DBG] #{i} start object-group network {cur_block[1]}", args.debug)
            continue

        m = re_svc_grp.match(ln_stripped)
        if m:
            cur_block = ("grp_svc", m.group(1))
            groups_svc.setdefault(cur_block[1], [])
            debug(f"[DBG] #{i} start object-group service {cur_block[1]}", args.debug)
            continue

        # Inside blocks: collect members
        if cur_block:
            t, name = cur_block
            if t == "obj_net" and re_net_line.match(ln_stripped):
                objects_net[name].append(ln_stripped)
                continue
            if t == "obj_svc" and re_svc_line.match(ln_stripped):
                objects_svc[name].append(ln_stripped)
                continue
            if t in ("grp_net", "grp_svc") and re_group_obj.match(ln_stripped):
                if t == "grp_net":
                    groups_net[name].append(ln_stripped)
                else:
                    groups_svc[name].append(ln_stripped)
                continue
            # If line clearly starts a new section, end current block
            if re_acl.match(ln_stripped) or re_nat.match(ln_stripped) or re_iface.match(ln_stripped) or ln_stripped.lower().startswith("object"):
                end_block()

        # ACLs
        m = re_acl.match(ln_stripped)
        if m:
            acl_name, action, proto, rest = m.groups()
            acls.append({
                "acl": acl_name,
                "action": action.lower(),
                "proto": proto.lower(),
                "rest": rest.strip(),
                "raw": ln_stripped
            })
            continue

        # NATs
        if re_nat.match(ln_stripped):
            nats.append({"raw": ln_stripped})
            continue

        # Interfaces
        if re_iface.match(ln_stripped):
            ifaces.append({"raw": ln_stripped})
            continue

    # Summaries
    print("[INFO] Parsed summary:")
    print("  object network      :", len(objects_net))
    print("  object service      :", len(objects_svc))
    print("  object-group network:", len(groups_net))
    print("  object-group service:", len(groups_svc))
    print("  access-lists        :", len(acls))
    print("  NAT lines           :", len(nats))
    print("  interface lines     :", len(ifaces))

    # Write outputs (always write something for visibility)
    def write_json(name, data):
        path = f"{prefix}_{name}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"[INFO] Wrote {name}: {path}")

    def write_csv(name, rows, columns):
        path = f"{prefix}_{name}.csv"
        pd.DataFrame(rows, columns=columns if rows else columns).to_csv(path, index=False)
        print(f"[INFO] Wrote {name}: {path}")

    write_json("objects_network", objects_net)
    write_json("objects_service", objects_svc)
    write_json("groups_network", groups_net)
    write_json("groups_service", groups_svc)
    write_csv("acls", acls, ["acl","action","proto","rest","raw"])
    write_csv("nats", nats, ["raw"])
    write_csv("interfaces", ifaces, ["raw"])

    # Extra: a simple exploded list of resolved tokens we recognize (very basic)
    # You can enrich this later.
    def explode_net_entry(entry):
        # returns kind, value(s)
        toks = entry.split()
        if toks[0].lower() == "host":
            return ("host", toks[1])
        if toks[0].lower() == "subnet" and len(toks) >= 3:
            return ("subnet", f"{toks[1]} {toks[2]}")
        if toks[0].lower() == "range" and len(toks) >= 3:
            return ("range", f"{toks[1]} {toks[2]}")
        return ("other", entry)

    exploded = []
    for oname, entries in objects_net.items():
        for e in entries:
            kind, val = explode_net_entry(e)
            exploded.append({"object": oname, "kind": kind, "value": val})

    write_csv("objects_network_exploded", exploded, ["object","kind","value"])

    print("[DONE] Parsing complete.")

if __name__ == "__main__":
    main()
