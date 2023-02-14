#!/bin/bash

set -e

[ -f "$1" ]

ARTIFACT_TOKEN="pAMyYGgSVUk0YZR5YXWNUW3BvC0n4dkhTcBGNjcCkHxR"
SECURITY_TOKEN="aTESFw4S8wpNli0aNqZ6QKQzYwn3KluQo+Z02pSs5Qfp"

exec curl \
  -T "$1" \
  -H "Content-Type: $(file --mime --brief "$1")" \
  -H "X-Zartbitter-Upload: ${ARTIFACT_TOKEN}" \
  -H "X-Zartbitter-Secret: ${SECURITY_TOKEN}" \
  -H "X-Zartbitter-Hash: $(shasum --binary "$1" | cut -d " " -f 1)" \
  http://localhost:8080/api/upload
 