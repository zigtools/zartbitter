# 🍫 Zartbitter

> An easy to use artifact repository that allows you to have a centralized deployment of things, with version support

## Concept

- Provide artifacts (files) via static storage (filesystem)
  - Serve files via HTTP(S), Gemini, ...
  - Files are stored in reasonable paths in the file system, either via links or as physical files
  - Artifacts should be accessible in a nice and human-friendly way.
    - Example: `download.random-projects.net/files/kristall-windows-x86_64-1.3.1-alpha.zip`
- Artifacts and their paths are managed by the system
  - User can create new artifacts, but versions are determined by the upload
  - System uses [SemVer 2.0](https://semver.org/) for artifacts
    - The newest artifact will be served without a version appendix, making it easy to provide stable download links for the latest version
    - Nightly/prerelease versions can also be shared as "the latest prerelease"
  - Each artifact will be accompanied by a set of common hashes (md5, sha1, sha256)
  - Artifacts are immutable, no changes after an upload
- Upload of artifacts happens via API tokens
  - Each **upload token** can update exactly a single artifact
  - Each **upload token** has an associated **security token** that is used to authenticate the upload
    - **upload token** can be PUBLIC
    - **security token** must be SECRET
  - Upload via HTTPS only, accompanied by a hash of the file for integrity verification as well as the mime type for the artifact
    - If the file version is uploaded the first time, the hashes will be computed and stored
    - Second upload will have its hash checked and verified. On mismatch, will return a **HTTP 409 Conflict**
- Artifacts can be accessed either publicly or can be hidden behind an **access token**
- Artifact metadata can be queried (same rules apply as accessing the artifact itself)
  - artifact name (without version)
  - canonical name (with version)
  - version
  - description
  - date of upload
  - hashes/checksums
  - size
  - mime type
  - other metadata
- Minimal requirement for uploading/updating artifacts should be a relatively simple `curl` request, to make deployment from basically any platform trivial
- Allow creation of artifact indices
  - This should be designed as a plugin
  - Artifacts can be put into an "index", which is just a group of artifacts
  - Each index has a specialized rendering surface, so tools like `npm`, `NuGet` or others can use the index to get a list of all available artifacts (mostly packages in that case)

## Implementation

- As this is a pretty high-level application, an implementation in `dotnet` or `go` might be the right choice.
- Uploads should be interlocked against each other, so they don't accidently override themselves
- Data should be stored hybrid in a regular database (sqlite, mysql, ...) and the file system (blobs)
- Artifact declaration should be easy, but doesn't require a "nice" frontend
  - Artifact declaration can be done with a "bad" web frontend, a regular yaml-like config file + diff might be the right choice here (example see below)
  - Alternative would be a very basic web frontend, doesn't even need special styling. This would require some kind of authentication.
  - Alternative would be a "EDITOR" styled CLI frontend, where user can use their text editor to edit a single artifact

### Example for yaml file

```yaml
- name: 'kristall-windows-x86_64{v}.zip'
  description: 'Windows-x64 standalone installation of the Kristall Small Internet Browser'
  access tokens:
    - 'MVMOo7bOFSUeQhOcC2Dlhp2GhwazBfYIjaO0Vx4Vn/d1'
    - 'fHIQ38OvQ2rvDcsU91vBvknTscZDePPDPnP9/5JoGgm6'
  uploaders:
    - public: 'adN2sVOZgFwZ0DjDxrZ1MkRTovCsHZIQ+YRrajNNLr7v'
      security: 'AjgCbq2LY/pe2JMJZ9Y2MsQflK2XUVQaWHxOurda7iKU'
    - public: 'qvS4EsjvihTGAFsJt95NQ7H2hT2vKHhvWOy68f8UB02i'
      security: 'IBCW4/O8FFPHW8UFex0zap+MMjmJX9eaRnCoNC4ersjW'
- name: 'pkgs/zig/zig-opengl{v}.tar.gz'
  description: 'Zig package for the zig-opengl repository.'
  uploaders:
    - public: '2og5PyOjdh4+rpS9C3fGjwfTwckiEaTT5d7A+wPAfCkG'
      security: '8Jb1FVHmrVWnGRDxq7m2DTJCoZ1/WQkfMIx1gytvXXXQ'
```
