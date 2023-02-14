using System;
using System.Text;
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

  [PreparedStatement("")]
  public SqliteCommand FooBar { get; private set; }

  [System.AttributeUsage(System.AttributeTargets.Property, Inherited = false, AllowMultiple = false)]
  sealed class PreparedStatementAttribute : System.Attribute
  {
    readonly string sql_code;

    // This is a positional argument
    public PreparedStatementAttribute(string sql_code)
    {
      this.sql_code = sql_code;
    }

    public string SqlCode
    {
      get { return this.sql_code; }
    }
  }

}
