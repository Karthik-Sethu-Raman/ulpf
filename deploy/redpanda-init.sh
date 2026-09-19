#!/bin/sh
set -e
# --if-not-exists (controller R10): any stack re-run against a surviving broker
# must not fail the topics service and block depends_on consumers.
rpk topic create --if-not-exists raw.logs -p 6
rpk topic create --if-not-exists normalized.events -p 6
rpk topic create --if-not-exists pipeline.dlq -p 3
