using System.Reflection;
using System.Text;
using Microsoft.Data.Sqlite;
using System.Net;
using System.Net.Http;

namespace Zartbitter;

static class Application
{
  static int Main(string[] args)
  {
    if (args.Length != 1)
    {
      Console.Error.WriteLine("usage: zartbitter <config file>");
      return 1;
    }

    var config_file_info = new FileInfo(Path.GetFullPath(args[0]));

    var root_directory = config_file_info.Directory ?? throw new IOException("The given file is not in a directory path?!");

    var database_file_info = new FileInfo(Path.Combine(root_directory.FullName, "zartbitter.db3"));
    var blob_storage_dir = root_directory.CreateSubdirectory("blob");
    var upload_storage_dir = root_directory.CreateSubdirectory("uploads");

    blob_storage_dir.Create();

    using var connection = new SqliteConnection($"Data Source=\"{database_file_info}\"");
    connection.Open();

    {
      var init_script = new StreamReader(OpenEmbeddedResource("init.sql"), Encoding.UTF8).ReadToEnd();
      foreach (var stmt in init_script.Split(';'))
      {
        using var init_cmd = connection.CreateCommand();
        init_cmd.CommandText = stmt;
        init_cmd.ExecuteNonQuery();
      }
    }

    var system_listener = new HttpListener();
    system_listener.Prefixes.Add("http://+:8080/"); // TODO: Add configuration options
    system_listener.Start();

    Log.Message("Ready.");

    var server = new Server(connection, system_listener);

    server.Run();

    return 0;
  }

  static Stream OpenEmbeddedResource(string path)
  {
    var assembly = Assembly.GetExecutingAssembly();
    return assembly.GetManifestResourceStream(path) ?? throw new FileNotFoundException(path);
  }
}

//   var command = connection.CreateCommand();
//   command.CommandText =
//   @"
//         SELECT name
//         FROM user
//         WHERE id = $id
//     ";
//   int id = 10;
//   command.Parameters.AddWithValue("$id", id);

//   using (var reader = command.ExecuteReader())
//   {
//     while (reader.Read())
//     {
//       var name = reader.GetString(0);

//       Console.WriteLine($"Hello, {name}!");
//     }
//   }
// }