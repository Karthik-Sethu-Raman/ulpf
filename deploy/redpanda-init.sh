#!/bin/sh
set -e
rpk topic create raw.logs -p 6
rpk topic create normalized.events -p 6
rpk topic create pipeline.dlq -p 3
