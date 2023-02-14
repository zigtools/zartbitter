#!/bin/bash

sqlite3 "demo/zartbitter.db3" << EOF

INSERT INTO "artifacts" ("unique_name", "description", "is_public") VALUES ('kristall-windows-x86_64{v}.zip', 'Windows-x64 standalone installation of the Kristall Small Internet Browser', 0);
INSERT INTO "artifacts" ("unique_name", "description", "is_public") VALUES ('pkgs/zig/zig-opengl{v}.tar.gz', 'Zig package for the zig-opengl repository.', 1);

INSERT INTO "access_tokens" ("artifact", "token", "expires_at") VALUES ('kristall-windows-x86_64{v}.zip', 'MVMOo7bOFSUeQhOcC2Dlhp2GhwazBfYIjaO0Vx4Vn/d1', NULL);
INSERT INTO "access_tokens" ("artifact", "token", "expires_at") VALUES ('kristall-windows-x86_64{v}.zip', 'fHIQ38OvQ2rvDcsU91vBvknTscZDePPDPnP9/5JoGgm6', NULL);

INSERT INTO "upload_tokens" ("artifact", "upload_token", "security_token", "expires_at") VALUES ('kristall-windows-x86_64{v}.zip', 'adN2sVOZgFwZ0DjDxrZ1MkRTovCsHZIQ+YRrajNNLr7v', 'AjgCbq2LY/pe2JMJZ9Y2MsQflK2XUVQaWHxOurda7iKU', NULL);
INSERT INTO "upload_tokens" ("artifact", "upload_token", "security_token", "expires_at") VALUES ('kristall-windows-x86_64{v}.zip', 'qvS4EsjvihTGAFsJt95NQ7H2hT2vKHhvWOy68f8UB02i', 'IBCW4/O8FFPHW8UFex0zap+MMjmJX9eaRnCoNC4ersjW', NULL);
INSERT INTO "upload_tokens" ("artifact", "upload_token", "security_token", "expires_at") VALUES ('pkgs/zig/zig-opengl{v}.tar.gz', '2og5PyOjdh4+rpS9C3fGjwfTwckiEaTT5d7A+wPAfCkG', '8Jb1FVHmrVWnGRDxq7m2DTJCoZ1/WQkfMIx1gytvXXXQ', NULL);

INSERT INTO "metadata" ("artifact", "key", "value", "is_public") VALUES ('kristall-windows-x86_64{v}.zip', 'author', 'Felix "xq" Queißner', 1);
INSERT INTO "metadata" ("artifact", "key", "value", "is_public") VALUES ('kristall-windows-x86_64{v}.zip', 'code', 'https://github.com/MasterQ32/kristall', 1);
INSERT INTO "metadata" ("artifact", "key", "value", "is_public") VALUES ('kristall-windows-x86_64{v}.zip', 'debian-pkg', 'kristall', 1);
INSERT INTO "metadata" ("artifact", "key", "value", "is_public") VALUES ('pkgs/zig/zig-opengl{v}.tar.gz', 'author', 'xq', 1);
INSERT INTO "metadata" ("artifact", "key", "value", "is_public") VALUES ('pkgs/zig/zig-opengl{v}.tar.gz', 'code', 'https://github.com/MasterQ32/zig-opengl/', 1);

EOF