# smbscan

Dependency-free SMB/NetBIOS scanner (Python 3.8+): reachability, NetBIOS hostname/MAC,
SMB version (v1/v2/v3.x) and signing status.

    python run.py --targets 192.168.1.0/24 -t 50 --timeout 2 -o out.json
    python run.py -f hosts.txt -o out.csv -v

Targets: `192.168.1.1`, `192.168.1.1-192.168.1.50`, `192.168.1.1-50`, `192.168.1.0/24`
(comma separated allowed), or a file with one per line (`#` comments).

Plugins live in `smbscan/plugins/` as `NN_name.py` and run in filename order per host;
each subclasses `Plugin` and returns a dict merged into the shared context
(`{"abort": True}` stops that host). Only scan networks you are authorized to test.
