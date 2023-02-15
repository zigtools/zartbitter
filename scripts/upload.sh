#!/bin/bash

set -e

[ -f "$1" ]

ARTIFACT_TOKEN="adN2sVOZgFwZ0DjDxrZ1MkRTovCsHZIQ+YRrajNNLr7v"
SECURITY_TOKEN="AjgCbq2LY/pe2JMJZ9Y2MsQflK2XUVQaWHxOurda7iKU"
VERSION_NUMBER="0.1.0-beta"

exec curl \
  -T "$1" \
  -H "Content-Type: $(file --mime --brief "$1")" \
  -H "X-Zartbitter-Upload: ${ARTIFACT_TOKEN}" \
  -H "X-Zartbitter-Secret: ${SECURITY_TOKEN}" \
  -H "X-Zartbitter-Version: ${VERSION_NUMBER}" \
  -H "X-Zartbitter-Hash: $(sha1sum --binary "$1" | cut -d " " -f 1)" \
  http://localhost:8080/api/upload
 