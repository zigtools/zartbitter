#!/bin/bash

set -e

[ -f "$1" ]

ARTIFACT_TOKEN="2og5PyOjdh4+rpS9C3fGjwfTwckiEaTT5d7A+wPAfCkG"
SECURITY_TOKEN="8Jb1FVHmrVWnGRDxq7m2DTJCoZ1/WQkfMIx1gytvXXXQ"
VERSION_NUMBER="0.1.0-beta"

exec curl \
  -T "$1" \
  -H "Content-Type: $(file --mime --brief "$1")" \
  -H "X-Zartbitter-Upload: ${ARTIFACT_TOKEN}" \
  -H "X-Zartbitter-Secret: ${SECURITY_TOKEN}" \
  -H "X-Zartbitter-Version: ${VERSION_NUMBER}" \
  -H "X-Zartbitter-Hash: $(sha1sum --binary "$1" | cut -d " " -f 1)" \
  http://localhost:8080/api/upload
 