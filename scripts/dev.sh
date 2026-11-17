#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/.."
if [ ! -f .env ]; then cp .env.example .env; echo "wrote .env"; fi
docker compose up --build "$@"
