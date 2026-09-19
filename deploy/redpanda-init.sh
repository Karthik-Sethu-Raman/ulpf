#!/bin/sh
set -e
# Idempotent (controller R10): any stack re-run against a surviving broker must
# not fail the topics service and block depends_on consumers. This image's rpk
# (redpanda v24.1.7) has no `topic create --if-not-exists` flag, so list the
# existing topics and create only the missing ones.
existing=$(rpk topic list | tail -n +2 | awk '{print $1}' | tr '\n' ' ')
create() {
  topic=$1
  partitions=$2
  case " $existing " in
    *" $topic "*) ;;
    *) rpk topic create "$topic" -p "$partitions" ;;
  esac
}
create raw.logs 6
create normalized.events 6
create pipeline.dlq 3
