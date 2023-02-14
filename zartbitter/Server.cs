using System.Net;
using System.Text;
using Microsoft.Data.Sqlite;

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
        var content_type = request.Headers["Content-Type"] ?? throw new HttpException(HttpStatusCode.BadRequest, "Content-Type is missing.");

        var temp_file_name = Path.Combine(UploadStorageDirectory.FullName, Path.ChangeExtension(Path.GetRandomFileName(), ".dat"));
        try
        {
          Log.Debug("Uploading to {0}", temp_file_name);

          using (var file = File.Open(temp_file_name, FileMode.Create, FileAccess.ReadWrite))
          {
            request.InputStream.CopyTo(file);
          }

        }
        finally
        {
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
  public HttpException(HttpStatusCode status_code) { this.StatusCode = status_code; }
  public HttpException(HttpStatusCode status_code, string message) : base(message) { this.StatusCode = status_code; }
  public HttpException(HttpStatusCode status_code, string message, System.Exception inner) : base(message, inner) { this.StatusCode = status_code; }
  protected HttpException(
    System.Runtime.Serialization.SerializationInfo info,
    System.Runtime.Serialization.StreamingContext context) : base(info, context) { }

  public HttpStatusCode StatusCode { get; }
}