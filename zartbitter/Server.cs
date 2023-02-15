using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using Semver;

namespace Zartbitter;

internal class Server
{
  private static readonly Encoding utf8_no_bom = new UTF8Encoding(false);

  private readonly Database database;
  private readonly HttpListener system_listener;

  public Server(Database database, HttpListener system_listener)
  {
    this.database = database;
    this.system_listener = system_listener;
  }

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

      Log.Debug("{1}-Request for url {0}", url, request.HttpMethod);
      foreach (var key in request.Headers.AllKeys)
      {
        Log.Debug("{0}: {1}", key!, request.Headers[key]!);
      }

      if (path == "/files")
      {
        // TODO: List all public files here
        Log.Debug("Requesting artifact listing");
      }
      else if (path == "/files/")
      {
        // Redirect to canonical path. Wouldn't make sense to query this
        // as an artifact, as artifact names must be unique and non-empty.
        response.Redirect("/files");
      }
      else if (path.StartsWith("/files/"))
      {
        var artifact_name = path.Substring("/files/".Length);

        Log.Debug("Requesting artifact content for '{0}'", artifact_name);
        // TODO: Serve files
      }
      else if (path == "/api/upload")
      {
        // TODO: Implement API upload endpoint
        Log.Debug("Requesting api: upload");

        if (request.HttpMethod.ToUpper() != "PUT")
          throw new HttpException(HttpStatusCode.MethodNotAllowed, "Method must be PUT");

        var upload_token = request.Headers["X-Zartbitter-Upload"] ?? throw new HttpException(HttpStatusCode.BadRequest, "X-Zartbitter-Upload is missing.");
        var secret_token = request.Headers["X-Zartbitter-Secret"] ?? throw new HttpException(HttpStatusCode.BadRequest, "X-Zartbitter-Secret is missing.");
        var content_hash = request.Headers["X-Zartbitter-Hash"] ?? throw new HttpException(HttpStatusCode.BadRequest, "X-Zartbitter-Hash is missing.");
        var version_number_str = request.Headers["X-Zartbitter-Version"] ?? throw new HttpException(HttpStatusCode.BadRequest, "X-Zartbitter-Version is missing.");
        var content_type = request.Headers["Content-Type"] ?? throw new HttpException(HttpStatusCode.BadRequest, "Content-Type is missing.");

        var version = SemVersion.Parse(version_number_str, SemVersionStyles.Strict);

        Log.Debug("Uploading data for version {0}", version);

        this.database.GetArtifactFromUploadToken.Prepare(
            ParameterBinding.Text("upload_token", upload_token)
        );
        var artifact_name = this.database.GetArtifactFromUploadToken.ExecuteScalar<string>() ?? throw new HttpException(HttpStatusCode.NotFound);

        this.database.VerifySecurityTokenCorrect.Prepare(
          ParameterBinding.Text("upload_token", upload_token),
          ParameterBinding.Text("security_token", secret_token)
        );
        var artifact_valid = this.database.VerifySecurityTokenCorrect.ExecuteScalar<long?>() ?? throw new HttpException(HttpStatusCode.NotFound);

        if (artifact_valid == 0)
        {
          throw new HttpException(HttpStatusCode.Unauthorized, "Access denied: Invalid security token.");
        }

        Log.Message("Upload {0}", artifact_name);

        var temp_file_name = Path.Combine(UploadStorageDirectory.FullName, Path.ChangeExtension(Path.GetRandomFileName(), ".dat"));
        var upload_ok = false;
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
            }
          }

          var hash_md5 = hash_md5_computer.GetHash();
          var hash_sha1 = hash_sha1_computer.GetHash();
          var hash_sha256 = hash_sha256_computer.GetHash();
          var hash_sha512 = hash_sha512_computer.GetHash();

          Log.Debug("MD5:    {0}", BitConverter.ToString(hash_md5));
          Log.Debug("SHA1:   {0}", BitConverter.ToString(hash_sha1));
          Log.Debug("SHA256: {0}", BitConverter.ToString(hash_sha256));
          Log.Debug("SHA512: {0}", BitConverter.ToString(hash_sha512));
        }
        finally
        {
          if (!upload_ok)
            File.Delete(temp_file_name);
        }
      }
      else if (path == "/api/metadata")
      {
        // TODO: Implement API upload endpoint
        Log.Debug("Requesting api: metadata");
      }
      else if (path == "/")
      {
        Log.Debug("Requesting front matter.");
        // TODO: List the regular api end points here
      }
      else
      {
        Log.Warning("User requested unknown path: '{0}'", path);
        response.StatusCode = (int)HttpStatusCode.NotFound;
      }
    }
    catch (HttpException ex)
    {
      response.StatusCode = (int)ex.StatusCode;
      using (var writer = new StreamWriter(response.OutputStream, utf8_no_bom))
      {
        writer.WriteLine(ex.Message);
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