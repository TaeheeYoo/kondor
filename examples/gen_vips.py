#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Generate VIP config JSON for kondor benchmarks."""

import json
import sys

def gen_config(num_vips, num_reals):
    vips = []
    for v in range(num_vips):
        reals = []
        for r in range(num_reals):
            reals.append({"address": f"10.0.{v + 1}.{r + 1}"})
        vips.append({
            "address": f"10.0.0.{100 + v}",
            "port": 80,
            "protocol": "udp",
            "reals": reals,
        })
    return vips

if __name__ == "__main__":
    nv = int(sys.argv[1]) if len(sys.argv) > 1 else 16
    nr = int(sys.argv[2]) if len(sys.argv) > 2 else 64
    print(json.dumps(gen_config(nv, nr), indent=4))
