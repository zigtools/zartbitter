using System.Net;
using Microsoft.Data.Sqlite;

namespace Zartbitter;

internal class Server
{
  private readonly SqliteConnection connection;
  private readonly HttpListener system_listener;

  public Server(SqliteConnection connection, HttpListener system_listener)
  {
    this.connection = connection;
    this.system_listener = system_listener;
  }

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

      Log.Debug("Request for url {0}", url);

      if (path == "/files")
      {
        // TODO: List all public files here
        Log.Debug("Requesting artifact listing");
      }
      else if (path == "/files/")
      {
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
