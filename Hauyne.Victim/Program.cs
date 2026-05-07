var pidFile = Path.Combine(Path.GetTempPath(), "hauyne-victim.pid");
File.WriteAllText(pidFile, Environment.ProcessId.ToString());
Console.WriteLine($"Victim started (PID {Environment.ProcessId})");
Thread.Sleep(TimeSpan.FromMinutes(5));
