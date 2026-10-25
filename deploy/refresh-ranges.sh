#!/bin/sh
# Weekly crawler-range refresh, run by mirage-crawl-ranges.timer.
#
# A stale range file is the dangerous state: an address an operator added
# after the snapshot gets called an impersonator. So this runs on a timer,
# and the sensor is restarted only when the ranges actually changed (it
# loads the file at startup).
#
# config/ inside the container is a named volume seeded once from the image,
# so a source-URL fix that arrives with `git pull` would never reach it. Step
# 1 copies the repo's `sources` map into the volume's file; the fetched
# `operators` there are left alone.
set -eu
cd /opt/mirage/mirage-crawl

ops_hash() {
    docker compose exec -T crawl python -c '
import hashlib, json
ops = json.load(open("config/crawler_ranges.json"))["operators"]
print(hashlib.sha256(json.dumps(ops, sort_keys=True).encode()).hexdigest())'
}

docker compose exec -T crawl python -c '
import json, sys
new = json.load(sys.stdin)
path = "config/crawler_ranges.json"
cur = json.load(open(path))
cur["sources"] = new["sources"]
json.dump(cur, open(path, "w"), indent=2)
' < config/crawler_ranges.json

before=$(ops_hash)
docker compose exec -T crawl python scripts/refresh_ranges.py
after=$(ops_hash)

if [ "$before" != "$after" ]; then
    echo "ranges changed; restarting crawl"
    docker compose restart crawl
else
    echo "ranges unchanged; no restart"
fi
