using System;

namespace Zartbitter;

internal static class Log
{
  public static void Write(LogLevel level, string message)
  {
    Console.Error.WriteLine("[{0}] {1}", level.ToString().ToUpper(), message);
  }

  public static void Debug(string msg) => Write(LogLevel.Debug, msg);
  public static void Debug(string fmt, params object[] args) => Debug(string.Format(fmt, args));

  public static void Message(string msg) => Write(LogLevel.Message, msg);
  public static void Message(string fmt, params object[] args) => Message(string.Format(fmt, args));

  public static void Warning(string msg) => Write(LogLevel.Warning, msg);
  public static void Warning(string fmt, params object[] args) => Warning(string.Format(fmt, args));

  public static void Error(string msg) => Write(LogLevel.Error, msg);
  public static void Error(string fmt, params object[] args) => Error(string.Format(fmt, args));

  public static void Fatal(string msg) => Write(LogLevel.Fatal, msg);
  public static void Fatal(string fmt, params object[] args) => Fatal(string.Format(fmt, args));
}

internal enum LogLevel
{
  Debug = 0,
  Message = 100,
  Warning = 200,
  Error = 300,
  Fatal = 400,
}