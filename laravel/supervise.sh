#!/bin/sh
# ACME portal supervisor — lab only.
#
# Apache is configured with a single prefork worker because the exploit needs
# "the same worker" for the producer and consumer requests. That worker is
# expected to die during exploitation (SIGSEGV / SIGABRT / heap corruption),
# which also takes down the parent. Restarting it automatically keeps the site
# alive so the lab can be exercised repeatedly without manual intervention.
#
# In a real deployment this is exactly the kind of "it just restarts, nobody
# noticed" behaviour that hides active exploitation.

while true; do
    apache2-foreground
    rc=$?
    echo "[supervisor] apache exited (rc=$rc), restarting in 1s" >&2
    sleep 1
done
