using System;
using System.Diagnostics;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;

namespace Zartbitter;

sealed class Database : IDisposable
{
  private SqliteConnection connection;

  public Database(string connection_string)
  {
    this.connection = new SqliteConnection(connection_string);
    this.connection.Open();

    var init_script = new StreamReader(Application.OpenEmbeddedResource("init.sql"), new UTF8Encoding(false)).ReadToEnd();
    foreach (var stmt in init_script.Split(';'))
    {
      using var init_cmd = this.connection.CreateCommand();
      init_cmd.CommandText = stmt;
      init_cmd.ExecuteNonQuery();
    }

    foreach (var prop in this.GetType().GetProperties())
    {
      var prepared_statement_info = prop.GetCustomAttribute<PreparedStatementAttribute>();
      if (prepared_statement_info == null)
        continue;

      var cmd = this.connection.CreateCommand();
      cmd.CommandText = prepared_statement_info.SqlCode;
      foreach (var param in prepared_statement_info.Parameters)
      {
        cmd.Parameters.Add(param.Key, param.Value);
      }
      prop.SetValue(this, cmd);
    }
  }

  ~Database()
  {
    this.Dispose();
  }

  public void Dispose()
  {
    this.connection.Dispose();
    GC.SuppressFinalize(this);
  }

  [PreparedStatement("SELECT artifact FROM upload_tokens WHERE upload_token == $upload_token[text]")]
  public SqliteCommand GetArtifactFromUploadToken { get; private set; }

  [PreparedStatement("SELECT security_token == $security_token[text] FROM upload_tokens WHERE upload_token == $upload_token[text]")]
  public SqliteCommand VerifySecurityTokenCorrect { get; private set; }

  [PreparedStatement("SELECT 1 FROM revisions WHERE artifact = $artifact[text] AND version = $artifact[version]")]
  public SqliteCommand CheckVersionExists { get; private set; }

  [PreparedStatement("INSERT INTO revisions (artifact, blob_storage_path, md5sum, sha1sum, sha256sum, sha512sum, creation_date, version) VALUES ($artifact[text], $path[text], $md5sum[text], $sha1sum[text], $sha256sum[text], $sha512sum[text], CURRENT_TIMESTAMP, $version[text]);")]
  public SqliteCommand CreateNewRevision { get; private set; }

  [System.AttributeUsage(System.AttributeTargets.Property, Inherited = false, AllowMultiple = false)]
  sealed class PreparedStatementAttribute : System.Attribute
  {
    private static readonly Regex parameter_regex = new Regex(@"(?<name>\$\w+)\[(?<type>\w+)\]");

    private readonly string sql_code;
    private readonly Dictionary<string, SqliteType> parameters;

    public PreparedStatementAttribute(string sql_code)
    {
      this.parameters = new Dictionary<string, SqliteType>();
      this.sql_code = parameter_regex.Replace(sql_code, (match) =>
      {
        var name = match.Groups["name"].Value;
        var type = Enum.Parse<SqliteType>(match.Groups["type"].Value, true);

        if (!this.parameters.TryAdd(name, type))
        {
          Debug.Assert(this.parameters[name] == type);
        }

        return name;
      });
    }

    public string SqlCode => this.sql_code;
    public Dictionary<string, SqliteType> Parameters => this.parameters;
  }

}
