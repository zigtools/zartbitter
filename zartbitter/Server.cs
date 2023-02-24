using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Mime;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Web;
using Microsoft.Data.Sqlite;
using Semver;
using zartbitter;

namespace Zartbitter;

internal class Server
{
  private static readonly Encoding utf8_no_bom = new UTF8Encoding(false);

  private readonly object upload_mutex = new object();

  private readonly Database database;
  private readonly HttpListener system_listener;

#pragma warning disable CS8618
  public Server(Database database, HttpListener system_listener)
  {
    this.database = database;
    this.system_listener = system_listener;
  }
#pragma warning restore CS8618

  public DirectoryInfo BlobStorageDirectory { get; set; }
  public DirectoryInfo UploadStorageDirectory { get; set; }

  public void Run()
  {
    while (true)
    {
      var context = this.system_listener.GetContext();
      ThreadPool.QueueUserWorkItem<HttpListenerContext>(this.AcceptConnection, context, false);
    }
  }

  private void AcceptConnection(HttpListenerContext context)
  {
    var request = context.Request;
    using var response = context.Response;

    try
    {
      var url = request.Url!;
      var path = url.AbsolutePath!;
      var query = HttpUtility.ParseQueryString(url.Query);

      Log.Debug("{1}-Request for url {0}", url, request.HttpMethod);

      if (path == "/")
      {
        response.ContentEncoding = utf8_no_bom;
        response.ContentType = "text/html";
        using (var sw = new StreamWriter(response.OutputStream, utf8_no_bom))
        {
          RenderFileListing(sw, "/", "Zartbitter Artifact Repository", null, new string[0], (emit) =>
          {
            emit(Icon.Dir, "artifacts", new string[0]);
            emit(Icon.Dir, "files", new string[0]);
          });
        }
      }
      else if (path == "/artifacts")
      {
        response.ContentEncoding = utf8_no_bom;
        response.ContentType = "text/html";
        using (var sw = new StreamWriter(response.OutputStream, utf8_no_bom))
        {
          RenderFileListing(sw, "/artifacts/", "Zartbitter Artifacts", Tuple.Create("/", "Overview"), new[] { "Description" }, (emit) =>
          {
            using (var reader = this.database.ListAllPublicArtifacts.ExecuteReader())
            {
              while (reader.Read())
              {
                var name = reader.GetString(0);
                var desc = reader.GetString(1);

                emit(Icon.File, name, new[] { desc });
              }
            }
          });
        }
      }
      else if (path == "/artifacts/")
      {
        // Redirect to canonical path. Wouldn't make sense to query this
        // as an artifact, as artifact names must be unique and non-empty.
        response.Redirect("/artifacts");
      }
      else if (path.StartsWith("/artifacts/"))
      {
        var artifact_name = HttpUtility.UrlDecode(path.Substring("/artifacts/".Length));

        if (!this.database.CheckArtifactExists(artifact_name))
          throw new HttpException(HttpStatusCode.NotFound);

        if (!this.database.CheckArtifactAccess(artifact_name, query["token"]))
          throw new HttpException(HttpStatusCode.Unauthorized);

        response.ContentEncoding = utf8_no_bom;
        response.ContentType = "text/html";
        using (var sw = new StreamWriter(response.OutputStream, utf8_no_bom))
        {
          RenderFileListing(sw, "/files/", "Zartbitter Artifact: " + artifact_name.Replace("{v}", ""), Tuple.Create("/artifacts", "Artifact List"), new[] { "Mime Type", "Date", "Size" }, (emit) =>
          {
            using (var reader = this.database.ListAllPublicFilesForArtifact.ExecuteReader(ParameterBinding.Text("artifact", artifact_name)))
            {
              // file_name, mime_type, creation_date, size
              while (reader.Read())
              {
                var name = reader.GetString(0);
                var mime = reader.GetString(1);
                var cdate = reader.GetString(2);
                var size = reader.GetInt64(3);

                emit(Icon.File, name, new[] { mime, cdate, GetBytesReadable(size) });
              }
            }
          });
        }
      }
      else if (path == "/files")
      {
        response.ContentEncoding = utf8_no_bom;
        response.ContentType = "text/html";
        using (var sw = new StreamWriter(response.OutputStream, utf8_no_bom))
        {
          RenderFileListing(sw, "/files/", "Zartbitter Files", Tuple.Create("/", "Overview"), new[] { "Mime Type", "Date", "Size" }, (emit) =>
          {
            using (var reader = this.database.ListAllPublicFiles.ExecuteReader())
            {
              // file_name, mime_type, creation_date, size
              while (reader.Read())
              {
                var name = reader.GetString(0);
                var mime = reader.GetString(1);
                var cdate = reader.GetString(2);
                var size = reader.GetInt64(3);

                emit(Icon.File, name, new[] { mime, cdate, GetBytesReadable(size) });
              }
            }
          });
        }
      }
      else if (path == "/files/")
      {
        // Redirect to canonical path. Wouldn't make sense to query this
        // as an artifact, as artifact names must be unique and non-empty.
        response.Redirect("/files");
      }
      else if (path.StartsWith("/files/"))
      {
        var file_name = path.Substring("/files/".Length);

        var info = this.GetArtifact(file_name, query["token"]);

        using (var reader = this.database.FetchRevisionInformation.ExecuteReader(ParameterBinding.Text("artifact", info.ArtifactID), ParameterBinding.Text("version", info.Version.ToString())))
        {
          Debug.Assert(reader.Read());

          var blob_storage_path = reader.GetString(0);
          var mime_type = reader.GetString(1);
          var md5sum = reader.GetString(2);
          var sha1sum = reader.GetString(3);
          var sha256sum = reader.GetString(4);
          var sha512sum = reader.GetString(5);

          response.ContentType = mime_type;
          response.AddHeader("X-Zartbitter-MD5", md5sum);
          response.AddHeader("X-Zartbitter-SHA1", sha1sum);
          response.AddHeader("X-Zartbitter-SHA256", sha256sum);
          response.AddHeader("X-Zartbitter-SHA512", sha512sum);

          using (var file_stream = File.Open(Path.Combine(this.BlobStorageDirectory.FullName, blob_storage_path), FileMode.Open, FileAccess.Read))
          {
            file_stream.CopyTo(response.OutputStream);
          }
        }
      }
      else if (path == "/api/upload")
      {
        // Perform the trivial request sanitizing:

        if (request.HttpMethod.ToUpper() != "PUT")
          throw new HttpException(HttpStatusCode.MethodNotAllowed, "Method must be PUT");

        var upload_token = request.Headers["X-Zartbitter-Upload"] ?? throw new HttpException(HttpStatusCode.BadRequest, "X-Zartbitter-Upload is missing.");
        var secret_token = request.Headers["X-Zartbitter-Secret"] ?? throw new HttpException(HttpStatusCode.BadRequest, "X-Zartbitter-Secret is missing.");
        var content_hash = request.Headers["X-Zartbitter-Hash"] ?? throw new HttpException(HttpStatusCode.BadRequest, "X-Zartbitter-Hash is missing.");
        var version_number_str = request.Headers["X-Zartbitter-Version"] ?? throw new HttpException(HttpStatusCode.BadRequest, "X-Zartbitter-Version is missing.");
        var content_type = request.Headers["Content-Type"] ?? throw new HttpException(HttpStatusCode.BadRequest, "Content-Type is missing.");

        var version = SemVersion.Parse(version_number_str, SemVersionStyles.Strict);

        // All parameters are present and have okayish form,
        // now verify them with a locked context:
        lock (this.upload_mutex)
        {
          var artifact_name = this.database.GetArtifactFromUploadToken.ExecuteScalar<string>(
            ParameterBinding.Text("upload_token", upload_token)
          ) ?? throw new HttpException(HttpStatusCode.NotFound);

          var token_pair_valid = this.database.VerifySecurityTokenCorrect.ExecuteScalar<long?>(
            ParameterBinding.Text("upload_token", upload_token),
            ParameterBinding.Text("security_token", secret_token)
          ) ?? throw new HttpException(HttpStatusCode.NotFound);
          if (token_pair_valid == 0)
          {
            throw new HttpException(HttpStatusCode.Unauthorized, "Access denied: Invalid security token.");
          }

          var version_exists = this.database.CheckVersionExists.ExecuteScalar<long?>(
            ParameterBinding.Text("artifact", artifact_name),
            ParameterBinding.Text("version", version.ToString())
          ) ?? 0L;
          if (version_exists == 1)
          {
            throw new HttpException(HttpStatusCode.Conflict, $"Conflict: Version {version} already exists!");
          }

          // Everything looks fine, we're authenticated, no version conflict is going to happen,
          // Let's upload the artifact

          Log.Message("Uploading new version {1} for artifact '{0}'", version, artifact_name);

          var temp_file_name = Path.Combine(UploadStorageDirectory.FullName, Path.ChangeExtension(Path.GetRandomFileName(), ".dat"));
          var delete_temp_file = true;
          var upload_successful = false;
          try
          {
            Log.Debug("Uploading to {0}", temp_file_name);

            var hash_md5_computer = new HashComputer(MD5.Create());
            var hash_sha1_computer = new HashComputer(SHA1.Create());
            var hash_sha256_computer = new HashComputer(SHA256.Create());
            var hash_sha512_computer = new HashComputer(SHA512.Create());

            var hashers = new[] {
              hash_md5_computer,
              hash_sha1_computer,
              hash_sha256_computer,
              hash_sha512_computer,
            };

            long copied_bytes = 0;
            using (var file = File.Open(temp_file_name, FileMode.Create, FileAccess.ReadWrite))
            {
              var chunk = new byte[8192];

              while (true)
              {
                int real_length = request.InputStream.Read(chunk, 0, chunk.Length);
                if (real_length == 0)
                  break;

                file.Write(chunk, 0, real_length);
                foreach (var item in hashers)
                {
                  item.Feed(chunk, 0, real_length);
                }
                copied_bytes += real_length;
              }
            }

            var hash_md5 = Convert.ToHexString(hash_md5_computer.GetHash()).ToLower();
            var hash_sha1 = Convert.ToHexString(hash_sha1_computer.GetHash()).ToLower();
            var hash_sha256 = Convert.ToHexString(hash_sha256_computer.GetHash()).ToLower();
            var hash_sha512 = Convert.ToHexString(hash_sha512_computer.GetHash()).ToLower();

            if (content_hash.ToLower() != hash_sha1)
            {
              throw new HttpException(HttpStatusCode.BadRequest, $"Checksum mismatch. The uploaded data has checksum {hash_sha1} while the provided checksum was {content_hash}!");
            }

            Log.Debug("MD5:    {0}", hash_md5);
            Log.Debug("SHA1:   {0}", hash_sha1);
            Log.Debug("SHA256: {0}", hash_sha256);
            Log.Debug("SHA512: {0}", hash_sha512);

            // Okay, we got a file on disk now that contains the data we want,
            // we know the hashes. Check if we know the file already, and if not,
            // let's put it into the blob storage:

            var blob_storage_path = this.database.CheckFileHashExists.ExecuteScalar<string?>(
               ParameterBinding.Text("checksum", hash_sha256)
            );

            if (blob_storage_path == null)
            {
              var extension = Path.GetExtension(artifact_name);

              var filename_hash_base = hash_sha256;
              Log.Debug("Could not find file with hash {0}, inserting into blob storage...", filename_hash_base);

              var file_name_len = 32;
              string? chosen_file_name = null;
              while (file_name_len < filename_hash_base.Length)
              {
                var file_name = filename_hash_base.Substring(0, file_name_len) + extension;
                file_name_len += 1;

                var chosen_full_path = Path.Combine(BlobStorageDirectory.FullName, file_name);
                if (!File.Exists(chosen_full_path))
                {
                  chosen_file_name = file_name;
                  break;
                }
              }
              if (file_name_len == filename_hash_base.Length)
              {
                // If we ever land here, we got a hash collision. Holy shitballs!
                // TODO: Figure out what to do here
                throw new HttpException(HttpStatusCode.Conflict, "You managed to get a SHA256 collision. Good job!");
              }
              Debug.Assert(chosen_file_name != null);


              var full_path = Path.Combine(BlobStorageDirectory.FullName, chosen_file_name);

              Log.Debug("Uploaded file as {0}, moving...", full_path);
              File.Move(temp_file_name, full_path, false);
              temp_file_name = full_path;
              blob_storage_path = chosen_file_name;
              delete_temp_file = false;
            }
            else
            {
              delete_temp_file = true;
              Log.Debug("Found equivalent file with same hash: {0}", blob_storage_path);
            }

            this.database.CreateNewRevision.ExecuteNonQuery(
              ParameterBinding.Text("artifact", artifact_name),
              ParameterBinding.Text("path", blob_storage_path),
              ParameterBinding.Text("md5sum", hash_md5),
              ParameterBinding.Text("sha1sum", hash_sha1),
              ParameterBinding.Text("sha256sum", hash_sha256),
              ParameterBinding.Text("sha512sum", hash_sha512),
              ParameterBinding.Text("version", version.ToString()),
              ParameterBinding.Integer("size", copied_bytes)
            );
            upload_successful = true;
          }
          finally
          {
            if (delete_temp_file || !upload_successful)
              File.Delete(temp_file_name);
          }
        }
      }
      else if (path == "/api/metadata")
      {
        var file_name = query["file_name"] ?? throw new HttpException(HttpStatusCode.BadRequest, "Missing file_name query.");

        var accepted_types = request.AcceptTypes!.Select(type => new ContentType(type)).ToArray();
        var available_types = new[]{
          new ContentType("text/plain"),
          new ContentType("text/json"),
          new ContentType("text/html"),
          // TODO: Implement XML query
          // new ContentType("text/xml"),
          // new ContentType("application/xml"),
        };

        var content_type = MatchMimeTypes(accepted_types, available_types) ?? throw new HttpException(HttpStatusCode.NotAcceptable);

        Log.Debug("Select content type: {0}", content_type);

        var info = this.GetArtifact(file_name, query["token"]);

        var tags = new List<Tuple<string, string>>();

        using (var reader = this.database.FetchArtifactMetadata.ExecuteReader(ParameterBinding.Text("artifact", info.ArtifactID)))
        {
          while (reader.Read())
          {
            var key = reader.GetString(0);
            var value = reader.GetString(1);
            var is_public = reader.GetInt64(2) != 0;

            tags.Add(Tuple.Create(key, value));
          }
        }

        var revisions = new List<Tuple<SemVersion>>();

        using (var reader = this.database.FetchRevisionInformation.ExecuteReader(ParameterBinding.Text("artifact", info.ArtifactID), ParameterBinding.Text("version", info.Version.ToString())))
        {
          Debug.Assert(reader.Read());

          var blob_storage_path = reader.GetString(0);
          var mime_type = reader.GetString(1);
          var md5sum = reader.GetString(2);
          var sha1sum = reader.GetString(3);
          var sha256sum = reader.GetString(4);
          var sha512sum = reader.GetString(5);

          response.ContentType = content_type.ToString();
          response.ContentEncoding = utf8_no_bom;
          using (var sw = new StreamWriter(response.OutputStream, utf8_no_bom))
          {
            switch (content_type.MediaType)
            {
              case "text/json":
                {
                  var tag_object = new JsonObject();

                  foreach (var item in tags)
                  {
                    tag_object[item.Item1] = item.Item2;
                  }

                  var root_object = new JsonObject
                  {
                    { "artifact", info.ArtifactID },
                    { "version", info.Version.ToString() },
                    { "mime_type", mime_type },
                    {
                      "hashes",
                      new JsonObject{
                        {"md5", md5sum},
                        {"sha1", sha1sum},
                        {"sha256", sha256sum},
                        {"sha512", sha512sum},
                      }
                    },
                    { "tags", tag_object },
                  };
                  sw.Write(root_object.ToString());
                }
                break;

              case "text/plain":
                {
                  sw.WriteLine("Artifact:  {0}", info.ArtifactID);
                  sw.WriteLine("Version:   {0}", info.Version.ToString());
                  sw.WriteLine("Mime type: {0}", mime_type);
                  sw.WriteLine("Hashes:");
                  sw.WriteLine("  MD5:    {0}", md5sum);
                  sw.WriteLine("  SHA1:   {0}", sha1sum);
                  sw.WriteLine("  SHA256: {0}", sha256sum);
                  sw.WriteLine("  SHA512: {0}", sha512sum);

                  if (tags.Count > 0)
                  {
                    sw.WriteLine("Tags:");
                    var width = tags.Select(s => s.Item1.Length).Max();
                    foreach (var item in tags)
                    {
                      sw.WriteLine("  {0} {1}", (item.Item1 + ":").PadRight(width + 1, ' '), item.Item2);
                    }
                  }
                }
                break;

              case "text/html":
                {
                  sw.WriteLine("<!doctype html>");
                  sw.WriteLine("<html><head><style>");
                  sw.WriteLine(@"table {border-collapse: collapse; text-align: left}
table td,table.list th { padding: 0.35em;}
table.list td {border-top: 1px solid silver;}
table.list td:nth-child(2),table.list th:nth-child(2){border-left: 1px solid silver;}
table.props th{font-weight: bold;}");
                  sw.WriteLine("</style></head><body>");
                  sw.WriteLine("<h1>{0}</h1>", HttpUtility.HtmlEncode(info.ArtifactID));
                  sw.WriteLine("<h2>Metadata</h2><table class=\"props\">");
                  sw.WriteLine("<tr><th>Version:</th><td>{0}</td>", HttpUtility.HtmlEncode(info.Version.ToString()));
                  sw.WriteLine("<tr><th>Mime type:</th><td>{0}</td>", HttpUtility.HtmlEncode(mime_type));
                  sw.WriteLine("</table>");
                  sw.WriteLine("<h2>Hashes</h2><table class=\"list\"><tr><th>Algorithm</th><th>Hash</th></tr>");
                  sw.WriteLine("<tr><td>MD5</td><td>{0}</td></tr>", HttpUtility.HtmlEncode(md5sum));
                  sw.WriteLine("<tr><td>SHA1</td><td>{0}</td></tr>", HttpUtility.HtmlEncode(sha1sum));
                  sw.WriteLine("<tr><td>SHA256</td><td>{0}</td></tr>", HttpUtility.HtmlEncode(sha256sum));
                  sw.WriteLine("<tr><td>SHA512</td><td>{0}</td></tr>", HttpUtility.HtmlEncode(sha512sum));
                  sw.WriteLine("</table>");

                  if (tags.Count > 0)
                  {
                    sw.WriteLine("<h2>Tags</h2><table class=\"list\"><tr><th>Tag</th><th>Value</th></tr>");
                    var width = tags.Select(s => s.Item1.Length).Max();
                    foreach (var item in tags)
                    {
                      if (Uri.TryCreate(item.Item2, new UriCreationOptions() { DangerousDisablePathAndQueryCanonicalization = true }, out var uri))
                      {
                        sw.WriteLine("<tr><td>{0}</td><td><a href=\"{2}\" target=\"_blank\">{1}</a></th>", HttpUtility.HtmlEncode(item.Item1), HttpUtility.HtmlEncode(item.Item2), uri.ToString());
                      }
                      else
                      {
                        sw.WriteLine("<tr><td>{0}</td><td>{1}</th>", HttpUtility.HtmlEncode(item.Item1), HttpUtility.HtmlEncode(item.Item2));
                      }
                    }
                    sw.WriteLine("</table>");
                  }
                  sw.WriteLine("</body></html>");
                }
                break;

              case "text/xml":
              case "application/xml":
                {
                  // TODO: Implement
                }
                break;


              default:
                Debug.Assert(false);
                break;
            }
          }
        }
      }
      else
      {
        try
        {
          using (var resource = Application.OpenEmbeddedResource(path.Substring(1).Replace("/", ".")))
          {
            response.ContentType = MimeTypes.GetMimeType(path);
            using (response.OutputStream)
              resource.CopyTo(response.OutputStream);
          }
        }
        catch (FileNotFoundException ex)
        {
          Log.Warning("User requested unknown path: '{0}' ({1})", path, ex.Message);
          response.StatusCode = (int)HttpStatusCode.NotFound;
        }
      }
    }
    catch (HttpException ex)
    {
      try
      {
        response.StatusCode = (int)ex.StatusCode;
        using (var writer = new StreamWriter(response.OutputStream, utf8_no_bom))
        {
          writer.WriteLine(ex.Message);
        }
      }
      catch (Exception subex)
      {
        Log.Error("Failed to reject HTTP request: {0}", subex.ToString());
      }
    }
    catch (Exception ex)
    {
      Log.Error("Failed to handle request at url {0}:", request.Url!);
      Log.Error(ex.ToString());
      try
      {
        response.StatusCode = (int)HttpStatusCode.InternalServerError;
      }
      catch
      {
        // silently ignore error
      }
    }
  }

  ContentType? MatchMimeTypes(ContentType[] accepted_types, ContentType[] available_types)
  {
    accepted_types = accepted_types
    .OrderByDescending(key => double.Parse(key.Parameters["q"] ?? "1.0", CultureInfo.InvariantCulture))
    .ToArray();

    foreach (var accepted_type in accepted_types)
    {
      var any_match = available_types.FirstOrDefault(available_type => IsMimeMatching(accepted_type, available_type));
      if (any_match != null)
        return any_match;
    }

    return null;
  }

  private bool IsMimeMatching(ContentType accepted_type, ContentType available_type)
  {
    if (accepted_type.MediaType == available_type.MediaType)
      return true;

    var split_accept = accepted_type.MediaType.Split('/');
    var split_avail = available_type.MediaType.Split('/');

    if (split_accept[1] == "*" && split_accept[0] == split_avail[0])
      return true;

    if (split_accept[0] == "*") // ignore */foo as it's illegal anyways
      return true;

    return false;

  }

  class ArtifactQueryResult
  {
    public string ArtifactID { get; set; }

    public SemVersion Version { get; set; }
  }

  private ArtifactQueryResult GetArtifact(string file_name, string? access_token)
  {
    string artifact_id;
    ArtifactVersionSelector version_selector;
    SemVersion? requested_artifact_version;

    if (this.database.CheckArtifactExists(file_name))
    {
      // this is direct access to stable version by using artifact name instead
      // of the actual file name
      artifact_id = file_name;
      version_selector = ArtifactVersionSelector.LatestStable;
      requested_artifact_version = null;
    }
    else
    {
      var maybe_latest_artifact = this.database.FindArtifactByVersionedFileName("unstable", file_name);
      if (maybe_latest_artifact != null)
      {
        // this is using a file with version "unstable" to get a link to the newest version
        artifact_id = maybe_latest_artifact;
        version_selector = ArtifactVersionSelector.LatestUnstable;
        requested_artifact_version = null;
      }
      else
      {
        // else we have to search via an explicit version
        using (var reader = this.database.ListAllArtifacts.ExecuteReader())
        {
          while (reader.Read())
          {
            var identifier = reader.GetString(0);
            var artifact_file_name = reader.GetString(1);

            var semver_regex_matcher = @"(?<semver>(?<major>0|[1-9]\d*)\.(?<minor>0|[1-9]\d*)\.(?<patch>0|[1-9]\d*)(?:-(?<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+(?<buildmetadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?)";

            var filename_version_extractor = "^" + Regex.Escape(artifact_file_name).Replace("\\{v}", semver_regex_matcher) + "$";

            // Log.Debug("Construct regex: {0}", filename_version_extractor);
            // Log.Debug("Test file name: {0}", file_name);

            var match = Regex.Match(file_name, filename_version_extractor);

            if (!match.Success)
              continue;

            artifact_id = identifier;
            requested_artifact_version = SemVersion.Parse(match.Groups["semver"].Value, SemVersionStyles.Strict);
            version_selector = ArtifactVersionSelector.Explicit;

            goto _found;
          }
          throw new HttpException(HttpStatusCode.NotFound);
        _found:
          ;
        }
      }
    }

    // Verify we can actually access the artifact at all.
    if (!this.database.CheckArtifactAccess(artifact_id, access_token))
    {
      throw new HttpException(HttpStatusCode.Unauthorized);
    }

    switch (version_selector)
    {
      case ArtifactVersionSelector.Explicit:
        Debug.Assert(requested_artifact_version != null);
        break;

      case ArtifactVersionSelector.LatestStable:
      case ArtifactVersionSelector.LatestUnstable:
        {
          var available_versions = new List<SemVersion>();

          using (var reader = this.database.ListAllArtifactVersions.ExecuteReader(ParameterBinding.Text("artifact", artifact_id)))
          {
            while (reader.Read())
            {
              var version_string = reader.GetString(0);
              var version = SemVersion.Parse(version_string, SemVersionStyles.Strict);

              // Filter out prereleases when looking at stable versions
              if (version.IsPrerelease && (version_selector == ArtifactVersionSelector.LatestStable))
                continue;

              available_versions.Add(version);
            }
          }

          if (available_versions.Count == 0)
          {
            throw new HttpException(HttpStatusCode.NotFound, "This artifact has no revisions.");
          }

          requested_artifact_version = available_versions.Max();
        }
        break;
    }

    Debug.Assert(requested_artifact_version != null);

    return new ArtifactQueryResult
    {
      ArtifactID = artifact_id,
      Version = requested_artifact_version!,
    };
  }

  private static readonly string file_table_template = new StreamReader(Application.OpenEmbeddedResource("file_table.html"), utf8_no_bom).ReadToEnd();
  private static readonly Regex file_table_pattern = new Regex(@"<!--\s*(\w+)\s*-->", RegexOptions.Compiled);

  public enum Icon
  {
    Dir,
    File,
    Up,
  }

  public static void RenderFileListing(StreamWriter writer, string link_prefix, string title, Tuple<string, string>? uplink, string[] columns, Action<Action<Icon, string, string[]>> items)
  {
    writer.WriteLine(file_table_pattern.Replace(file_table_template, (match) =>
    {
      var key = match.Groups[1].Value.ToUpper();
      switch (key)
      {
        case "TITLE": return title;

        case "UPLINK":
          using (var tw = new StringWriter())
          {
            if (uplink != null)
            {
              tw.WriteLine("  <div id=\"parentDirLinkBox\">");
              tw.WriteLine("    <a id=\"parentDirLink\" class=\"icon up\" href=\"{0}\">", uplink.Item1);
              tw.WriteLine("      <span id=\"parentDirText\">{0}</span>", uplink.Item2);
              tw.WriteLine("    </a>");
              tw.WriteLine("  </div>");
            }
            return tw.ToString();
          }

        case "COLUMNS":
          using (var tw = new StringWriter())
          {
            foreach (var col in columns)
            {
              tw.WriteLine("  <th id=\"dateColumnHeader\" class=\"detailsColumn\" tabindex=0 role=\"button\">");
              tw.WriteLine("    {0}", col);
              tw.WriteLine("  </th>");
            }
            return tw.ToString();
          }

        case "ITEMS":
          using (var tw = new StringWriter())
          {
            items((icon, filename, fields) =>
            {
              tw.WriteLine("  <tr>");
              tw.WriteLine("    <td><a class=\"icon {2}\" href=\"{1}{0}\">{0}</a></td>", filename, link_prefix, icon.ToString().ToLower());
              foreach (var field in fields)
              {
                tw.WriteLine("    <td class=\"detailsColumn\">{0}</td>", field);
              }
              tw.WriteLine("  </tr>");
            });
            return tw.ToString();
          }

        default:
          return "<!-- UNKNOWN PATTERN: " + key + " -->";
      }
    }));
  }

  // Returns the human-readable file size for an arbitrary, 64-bit file size 
  // The default format is "0.### XB", e.g. "4.2 KB" or "1.434 GB"
  public static string GetBytesReadable(long i)
  {
    // Get absolute value
    long absolute_i = (i < 0 ? -i : i);
    // Determine the suffix and readable value
    string suffix;
    double readable;
    if (absolute_i >= 0x1000000000000000) // Exabyte
    {
      suffix = "EB";
      readable = (i >> 50);
    }
    else if (absolute_i >= 0x4000000000000) // Petabyte
    {
      suffix = "PB";
      readable = (i >> 40);
    }
    else if (absolute_i >= 0x10000000000) // Terabyte
    {
      suffix = "TB";
      readable = (i >> 30);
    }
    else if (absolute_i >= 0x40000000) // Gigabyte
    {
      suffix = "GB";
      readable = (i >> 20);
    }
    else if (absolute_i >= 0x100000) // Megabyte
    {
      suffix = "MB";
      readable = (i >> 10);
    }
    else if (absolute_i >= 0x400) // Kilobyte
    {
      suffix = "KB";
      readable = i;
    }
    else
    {
      return i.ToString("0 B"); // Byte
    }
    // Divide by 1024 to get fractional value
    readable = (readable / 1024);
    // Return formatted number with suffix
    return readable.ToString("0.### ") + suffix;
  }
}

[System.Serializable]
public class HttpException : System.Exception
{
  public HttpException(HttpStatusCode status_code) : this(status_code, status_code.ToString()) { }
  public HttpException(HttpStatusCode status_code, string message) : base(message) { this.StatusCode = status_code; }
  public HttpException(HttpStatusCode status_code, string message, System.Exception inner) : base(message, inner) { this.StatusCode = status_code; }
  protected HttpException(
    System.Runtime.Serialization.SerializationInfo info,
    System.Runtime.Serialization.StreamingContext context) : base(info, context) { }

  public HttpStatusCode StatusCode { get; }
}

public sealed class HashComputer
{
  private readonly HashAlgorithm hasher;

  public HashComputer(HashAlgorithm hasher)
  {
    this.hasher = hasher;
  }

  public void Feed(byte[] chunk, int offset, int length)
  {
    hasher.TransformBlock(chunk, offset, length, null, 0);
  }

  public byte[] GetHash()
  {
    this.hasher.TransformFinalBlock(new byte[0], 0, 0);
    return this.hasher.Hash!.ToArray();
  }
}

public enum ArtifactVersionSelector
{
  Explicit,
  LatestUnstable,
  LatestStable,
}