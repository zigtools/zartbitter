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

      try
      {
        var stmt = new PreparedStatement(this.connection, prepared_statement_info.SqlCode);
        prop.SetValue(this, stmt);
      }
      catch (Exception ex)
      {
        Log.Fatal("Failed to prepare statement {0}: {1}", prop.Name, ex.Message);
        Log.Fatal("SQL Code: {0}", prepared_statement_info.SqlCode);
        throw;
      }
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

  public bool DoesArtifactExist(string artifact_name)
  {
    return this.CheckArtifactExists.ExecuteBoolean(ParameterBinding.Text("artifact", artifact_name)) ?? false;
  }

  public bool CheckArtifactAccess(string artifact_name, string? token)
  {
    return this.CheckArtifactAccessStmt.ExecuteBoolean(ParameterBinding.Text("artifact", artifact_name), ParameterBinding.Text("token", token)) ?? false;
  }

  [PreparedStatement("SELECT artifact FROM upload_tokens WHERE upload_token == $upload_token[text]")]
  public PreparedStatement GetArtifactFromUploadToken { get; private set; }

  [PreparedStatement("SELECT security_token == $security_token[text] FROM upload_tokens WHERE upload_token == $upload_token[text]")]
  public PreparedStatement VerifySecurityTokenCorrect { get; private set; }

  [PreparedStatement("SELECT 1 FROM revisions WHERE artifact = $artifact[text] AND version = $version[text]")]
  public PreparedStatement CheckVersionExists { get; private set; }

  [PreparedStatement("SELECT 1 FROM artifacts WHERE unique_name = $artifact[text]")]
  public PreparedStatement CheckArtifactExists { get; private set; }

  [PreparedStatement("SELECT 1 FROM access_tokens INNER JOIN artifacts ON artifacts.unique_name == access_tokens.artifact WHERE artifact == $artifact[text] AND (token == $token[text] OR (token IS NULL AND artifacts.is_public))")]
  public PreparedStatement CheckArtifactAccessStmt { get; private set; }

  [PreparedStatement("SELECT blob_storage_path FROM revisions WHERE sha256sum = $checksum[text]")]
  public PreparedStatement CheckFileHashExists { get; private set; }

  [PreparedStatement("INSERT INTO revisions (artifact, blob_storage_path, md5sum, sha1sum, sha256sum, sha512sum, creation_date, version, size) VALUES ($artifact[text], $path[text], $md5sum[text], $sha1sum[text], $sha256sum[text], $sha512sum[text], CURRENT_TIMESTAMP, $version[text], $size[integer])")]
  public PreparedStatement CreateNewRevision { get; private set; }

  [PreparedStatement("SELECT REPLACE(artifact, \"{v}\", version) AS file_name, mime_type, creation_date, size FROM revisions INNER JOIN artifacts ON artifacts.unique_name = revisions.artifact AND artifacts.is_public ORDER BY artifact")]
  public PreparedStatement ListAllPublicFiles { get; private set; }

  [PreparedStatement("SELECT REPLACE(artifact, \"{v}\", version) AS file_name, mime_type, creation_date, size FROM revisions INNER JOIN artifacts ON artifacts.unique_name = revisions.artifact WHERE revisions.artifact = $artifact[text] ORDER BY artifact")]
  public PreparedStatement ListAllPublicFilesForArtifact { get; private set; }

  [PreparedStatement("SELECT REPLACE(unique_name, \"{v}\", \"\") AS file_name, description FROM artifacts WHERE is_public ORDER BY unique_name")]
  public PreparedStatement ListAllPublicArtifacts { get; private set; }

  public class PreparedStatement
  {
    private static readonly Regex parameter_regex = new Regex(@"(?<name>\$\w+)\[(?<type>\w+)\]");

    private readonly SqliteCommand command;
    private readonly string sql_code;
    private readonly Dictionary<string, SqliteType> parameters;

    internal PreparedStatement(SqliteConnection con, string command)
    {
      this.parameters = new Dictionary<string, SqliteType>();
      this.sql_code = parameter_regex.Replace(command, (match) =>
      {
        var name_str = match.Groups["name"].Value;
        var type_str = match.Groups["type"].Value;

        var name = name_str.Substring(1);
        var type = Enum.Parse<SqliteType>(type_str, true);

        if (!this.parameters.TryAdd(name, type))
        {
          Debug.Assert(this.parameters[name] == type);
        }

        return "$" + name;
      });

      this.command = con.CreateCommand();
      this.command.CommandText = this.sql_code;
      foreach (var param in this.parameters)
      {
        this.command.Parameters.Add("$" + param.Key, param.Value);
      }
      this.command.Prepare();
    }

    private void Prepare(params ParameterBinding[] bindings)
    {
      if (bindings.Length > this.parameters.Count)
        throw new ArgumentOutOfRangeException(nameof(bindings), "Too many bindings for this command.");
      var bindings_dict = bindings.ToDictionary(b => b.Key);
      if (bindings_dict.Count != bindings.Length)
        throw new ArgumentOutOfRangeException(nameof(bindings), "Duplicate keys!");
      foreach (var kv in bindings_dict)
      {
        if (!this.parameters.TryGetValue(kv.Key, out var src_type))
          throw new ArgumentOutOfRangeException(nameof(bindings), "Unknown parameter: " + kv.Key);
        if (kv.Value.Type != src_type)
          throw new ArgumentOutOfRangeException(nameof(bindings), $"Type mismatch: Expected {src_type}, got {kv.Value.Type} for parameter {kv.Key}");
      }
      foreach (var kv in bindings_dict)
      {
        this.command.Parameters["$" + kv.Key].Value = kv.Value.Value ?? DBNull.Value;
      }
    }

    public bool? ExecuteBoolean(params ParameterBinding[] bindings)
    {
      var is_true = this.ExecuteScalar<long?>(bindings);
      if (is_true == null)
        return null;
      return (is_true != 0);
    }

    public T? ExecuteScalar<T>(params ParameterBinding[] bindings)
    {
      lock (this.command)
      {
        this.Prepare(bindings);
        return (T?)this.command.ExecuteScalar();
      }
    }

    public SqliteDataReader ExecuteReader(params ParameterBinding[] bindings)
    {
      lock (this.command)
      {
        this.Prepare(bindings);
        return this.command.ExecuteReader();
      }
    }

    public void ExecuteNonQuery(params ParameterBinding[] bindings)
    {
      lock (this.command)
      {
        this.Prepare(bindings);
        this.command.ExecuteNonQuery();
      }
    }
  }

  [System.AttributeUsage(System.AttributeTargets.Property, Inherited = false, AllowMultiple = false)]
  sealed class PreparedStatementAttribute : System.Attribute
  {
    readonly string sql_code;
    public PreparedStatementAttribute(string sql_code)
    {
      this.sql_code = sql_code;
    }

    public string SqlCode
    {
      get { return sql_code; }
    }
  }
}


public class ParameterBinding
{
  private ParameterBinding(SqliteType type, string key, object? value)
  {
    this.Type = type;
    this.Key = key;
    this.Value = value;
  }

  public static ParameterBinding Text(string key, string? value) => new ParameterBinding(SqliteType.Text, key, value);
  public static ParameterBinding Integer(string key, long? value) => new ParameterBinding(SqliteType.Integer, key, value);
  public static ParameterBinding Blob(string key, byte[]? value) => new ParameterBinding(SqliteType.Blob, key, value);
  public static ParameterBinding Real(string key, double? value) => new ParameterBinding(SqliteType.Real, key, value);

  public SqliteType Type { get; }
  public string Key { get; }
  public object? Value { get; }
}