using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace MasterSecurityReviewLauncher
{
    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
            try
            {
                EnsureRunningAsAdministrator();
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    "No se pudo iniciar la aplicación con privilegios de administrador.\n\n" + ex.Message,
                    "MASTER SECURITY REVIEW",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                return;
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }

        private static void EnsureRunningAsAdministrator()
        {
            if (IsAdministrator())
                return;

            var exePath = Application.ExecutablePath;
            var psi = new ProcessStartInfo
            {
                FileName = exePath,
                UseShellExecute = true,
                Verb = "runas",
                WorkingDirectory = Path.GetDirectoryName(exePath) ?? Environment.CurrentDirectory
            };

            try
            {
                Process.Start(psi);
            }
            catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
            {
                MessageBox.Show(
                    "La aplicación necesita permisos de administrador para realizar la auditoría completa.\n\n" +
                    "Has cancelado la elevación UAC. El análisis no se ejecutará.",
                    "Permisos requeridos",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
                throw new OperationCanceledException("Elevación UAC cancelada.", ex);
            }

            Environment.Exit(0);
        }

        private static bool IsAdministrator()
        {
            using (var identity = WindowsIdentity.GetCurrent())
            {
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }
    }

    internal sealed class MainForm : Form
    {
        private const int PowerShellTimeoutMs = 45 * 60 * 1000;

        private readonly RadioButton rbFull;
        private readonly RadioButton rbReview;
        private readonly RadioButton rbCustom;
        private readonly CheckBox chkIncludeSha;
        private readonly ComboBox cboPathMode;
        private readonly ComboBox cboCommandLineMode;
        private readonly ComboBox cboIdMode;
        private readonly ComboBox cboNetworkMode;
        private readonly GroupBox grpCustom;
        private readonly Button btnRun;
        private readonly ProgressBar progressBar;
        private readonly Label lblStatus;

        public MainForm()
        {
            Text = "MASTER SECURITY REVIEW";
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            ClientSize = new Size(680, 470);
            Font = new Font("Segoe UI", 9F, FontStyle.Regular, GraphicsUnit.Point);

            var lblTitle = new Label
            {
                Text = "MASTER SECURITY REVIEW v3.4.1",
                AutoSize = true,
                Font = new Font("Segoe UI", 16F, FontStyle.Bold, GraphicsUnit.Point),
                Location = new Point(24, 18)
            };
            Controls.Add(lblTitle);

            var lblSubtitle = new Label
            {
                Text = "Lanzador gráfico para ejecutar la auditoría de seguridad sin consola visible.",
                AutoSize = true,
                ForeColor = Color.DimGray,
                Location = new Point(26, 52)
            };
            Controls.Add(lblSubtitle);

            var grpPrivacy = new GroupBox
            {
                Text = "Modo de privacidad",
                Location = new Point(24, 88),
                Size = new Size(632, 118)
            };
            Controls.Add(grpPrivacy);

            rbFull = new RadioButton
            {
                Text = "FULL / INTERNO",
                AutoSize = true,
                Location = new Point(18, 28)
            };
            grpPrivacy.Controls.Add(rbFull);

            var lblFull = new Label
            {
                Text = "Máximo detalle. Úsalo solo para revisión local. No recomendado para compartir.",
                AutoSize = false,
                Size = new Size(590, 18),
                Location = new Point(38, 50),
                ForeColor = Color.DimGray
            };
            grpPrivacy.Controls.Add(lblFull);

            rbReview = new RadioButton
            {
                Text = "REVIEW / CHAT-SAFE (recomendado)",
                AutoSize = true,
                Checked = true,
                Location = new Point(18, 72)
            };
            grpPrivacy.Controls.Add(rbReview);

            var lblReview = new Label
            {
                Text = "Oculta rutas, IDs, hashes y datos de red sensibles, conservando contexto útil para revisar el informe.",
                AutoSize = false,
                Size = new Size(590, 18),
                Location = new Point(38, 94),
                ForeColor = Color.DimGray
            };
            grpPrivacy.Controls.Add(lblReview);

            rbCustom = new RadioButton
            {
                Text = "PERSONALIZADO",
                AutoSize = true,
                Location = new Point(380, 28)
            };
            grpPrivacy.Controls.Add(rbCustom);

            grpCustom = new GroupBox
            {
                Text = "Opciones de PERSONALIZADO",
                Location = new Point(24, 220),
                Size = new Size(632, 136),
                Enabled = false
            };
            Controls.Add(grpCustom);

            chkIncludeSha = new CheckBox
            {
                Text = "Incluir hashes SHA256 completos",
                AutoSize = true,
                Location = new Point(18, 28)
            };
            grpCustom.Controls.Add(chkIncludeSha);

            var lblPath = CreateLabel("Rutas:", 18, 62);
            var lblCmd = CreateLabel("CommandLine:", 322, 62);
            var lblId = CreateLabel("IDs:", 18, 96);
            var lblNet = CreateLabel("Red/IPs:", 322, 96);

            grpCustom.Controls.Add(lblPath);
            grpCustom.Controls.Add(lblCmd);
            grpCustom.Controls.Add(lblId);
            grpCustom.Controls.Add(lblNet);

            cboPathMode = CreateComboBox(90, 58, new[] { "Full", "Redacted", "Hidden" }, "Redacted");
            cboCommandLineMode = CreateComboBox(420, 58, new[] { "Full", "Redacted", "Hidden" }, "Redacted");
            cboIdMode = CreateComboBox(90, 92, new[] { "Full", "Masked", "Hidden" }, "Masked");
            cboNetworkMode = CreateComboBox(420, 92, new[] { "Full", "Masked", "Hidden" }, "Masked");

            grpCustom.Controls.Add(cboPathMode);
            grpCustom.Controls.Add(cboCommandLineMode);
            grpCustom.Controls.Add(cboIdMode);
            grpCustom.Controls.Add(cboNetworkMode);

            btnRun = new Button
            {
                Text = "EJECUTAR ANÁLISIS",
                Font = new Font("Segoe UI", 12F, FontStyle.Bold, GraphicsUnit.Point),
                Size = new Size(632, 52),
                Location = new Point(24, 372),
                BackColor = Color.FromArgb(0, 120, 215),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            btnRun.FlatAppearance.BorderSize = 0;
            btnRun.Click += async (s, e) => await RunAnalysisAsync();
            Controls.Add(btnRun);

            progressBar = new ProgressBar
            {
                Location = new Point(24, 432),
                Size = new Size(420, 12),
                Style = ProgressBarStyle.Blocks
            };
            Controls.Add(progressBar);

            lblStatus = new Label
            {
                Text = "Listo para ejecutar.",
                AutoSize = false,
                Size = new Size(210, 18),
                TextAlign = ContentAlignment.MiddleRight,
                Location = new Point(446, 428),
                ForeColor = Color.DimGray
            };
            Controls.Add(lblStatus);

            rbFull.CheckedChanged += PrivacyModeChanged;
            rbReview.CheckedChanged += PrivacyModeChanged;
            rbCustom.CheckedChanged += PrivacyModeChanged;
        }

        private static Label CreateLabel(string text, int x, int y)
        {
            return new Label
            {
                Text = text,
                AutoSize = true,
                Location = new Point(x, y + 4)
            };
        }

        private static ComboBox CreateComboBox(int x, int y, string[] items, string defaultValue)
        {
            var combo = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                Location = new Point(x, y),
                Size = new Size(170, 24)
            };
            combo.Items.AddRange(items);
            combo.SelectedItem = defaultValue;
            return combo;
        }

        private void PrivacyModeChanged(object sender, EventArgs e)
        {
            grpCustom.Enabled = rbCustom.Checked;
        }

        private PrivacyConfig GetPrivacyConfig()
        {
            if (rbFull.Checked)
            {
                return new PrivacyConfig
                {
                    ModeChoice = "1",
                    IncludeSHA = true,
                    PathMode = "Full",
                    CommandLineMode = "Full",
                    IdMode = "Full",
                    NetworkMode = "Full"
                };
            }

            if (rbReview.Checked)
            {
                return new PrivacyConfig
                {
                    ModeChoice = "2",
                    IncludeSHA = false,
                    PathMode = "Redacted",
                    CommandLineMode = "Redacted",
                    IdMode = "Masked",
                    NetworkMode = "Masked"
                };
            }

            return new PrivacyConfig
            {
                ModeChoice = "3",
                IncludeSHA = chkIncludeSha.Checked,
                PathMode = cboPathMode.SelectedItem?.ToString() ?? "Redacted",
                CommandLineMode = cboCommandLineMode.SelectedItem?.ToString() ?? "Redacted",
                IdMode = cboIdMode.SelectedItem?.ToString() ?? "Masked",
                NetworkMode = cboNetworkMode.SelectedItem?.ToString() ?? "Masked"
            };
        }

        private async Task RunAnalysisAsync()
        {
            var config = GetPrivacyConfig();
            SetUiBusy(true, "Analizando...");

            try
            {
                var result = await Task.Run(() => ExecuteEmbeddedPowerShell(config));
                SetUiBusy(false, result.Success ? "Completado." : "Error.");

                if (result.Success)
                {
                    var msg = string.IsNullOrWhiteSpace(result.ReportPath)
                        ? "El análisis terminó correctamente. El informe se ha guardado en el Escritorio."
                        : "El análisis terminó correctamente.\n\nInforme guardado en:\n" + result.ReportPath;

                    MessageBox.Show(
                        msg,
                        "Análisis completado",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information);
                }
                else
                {
                    MessageBox.Show(
                        result.ErrorMessage,
                        "Error durante el análisis",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error);
                }
            }
            catch (Exception ex)
            {
                SetUiBusy(false, "Error.");
                MessageBox.Show(
                    "Se produjo un error no controlado:\n\n" + ex,
                    "MASTER SECURITY REVIEW",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
        }

        private void SetUiBusy(bool busy, string status)
        {
            if (InvokeRequired)
            {
                Invoke(new Action<bool, string>(SetUiBusy), busy, status);
                return;
            }

            rbFull.Enabled = !busy;
            rbReview.Enabled = !busy;
            rbCustom.Enabled = !busy;
            grpCustom.Enabled = !busy && rbCustom.Checked;
            btnRun.Enabled = !busy;

            progressBar.Style = busy ? ProgressBarStyle.Marquee : ProgressBarStyle.Blocks;
            progressBar.MarqueeAnimationSpeed = busy ? 28 : 0;
            lblStatus.Text = status;
            lblStatus.ForeColor = busy ? Color.FromArgb(0, 120, 215) : Color.DimGray;
        }

        private static ExecutionResult ExecuteEmbeddedPowerShell(PrivacyConfig config)
        {
            string psExe = ResolvePowerShellExe();
            if (string.IsNullOrWhiteSpace(psExe))
            {
                return ExecutionResult.Fail(
                    "No se encontró powershell.exe en el sistema. Esta aplicación requiere Windows PowerShell 5.1, que viene integrado en Windows 10 y Windows 11.");
            }

            string tempDir = null;
            string scriptPath = null;
            string logPath = null;
            string stdout = string.Empty;
            string stderr = string.Empty;

            try
            {
                string wrappedScript = BuildWrappedPowerShellScript(config);

                tempDir = CreateTempRunDirectory();
                scriptPath = Path.Combine(tempDir, "MSR_wrapped.ps1");
                logPath = Path.Combine(tempDir, "MSR_launcher_debug.txt");

                WriteUtf8BomFile(scriptPath, wrappedScript);

                var psi = new ProcessStartInfo
                {
                    FileName = psExe,
                    Arguments = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File " + QuoteArg(scriptPath),
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    WorkingDirectory = tempDir,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    StandardOutputEncoding = Encoding.UTF8,
                    StandardErrorEncoding = Encoding.UTF8
                };

                using (var process = new Process { StartInfo = psi })
                {
                    process.Start();

                    Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync();
                    Task<string> stderrTask = process.StandardError.ReadToEndAsync();

                    bool exited = process.WaitForExit(PowerShellTimeoutMs);
                    if (!exited)
                    {
                        TryKillProcess(process);
                        TryWaitTasks(stdoutTask, stderrTask, 5000);

                        stdout = GetTaskResult(stdoutTask);
                        stderr = GetTaskResult(stderrTask);

                        WriteDiagnosticLog(logPath, psi, scriptPath, timedOut: true, exitCode: null, stdout: stdout, stderr: stderr);

                        return ExecutionResult.Fail(
                            BuildFailureMessage(
                                "La ejecución del script excedió el tiempo máximo permitido y fue cancelada.",
                                scriptPath,
                                logPath,
                                stdout,
                                stderr,
                                null));
                    }

                    Task.WaitAll(stdoutTask, stderrTask);
                    process.WaitForExit();

                    stdout = stdoutTask.Result ?? string.Empty;
                    stderr = stderrTask.Result ?? string.Empty;

                    string reportPath = ExtractReportPath(stdout) ?? ExtractReportPath(stderr);
                    WriteDiagnosticLog(logPath, psi, scriptPath, timedOut: false, exitCode: process.ExitCode, stdout: stdout, stderr: stderr);

                    if (process.ExitCode == 0)
                    {
                        return ExecutionResult.Ok(reportPath, scriptPath, logPath);
                    }

                    return ExecutionResult.Fail(
                        BuildFailureMessage(
                            "La ejecución del script no finalizó correctamente.",
                            scriptPath,
                            logPath,
                            stdout,
                            stderr,
                            process.ExitCode));
                }
            }
            catch (Exception ex)
            {
                TryWriteText(logPath,
                    "Excepción no controlada en ExecuteEmbeddedPowerShell" + Environment.NewLine +
                    ex + Environment.NewLine + Environment.NewLine +
                    "ScriptPath=" + (scriptPath ?? "(null)") + Environment.NewLine);

                return ExecutionResult.Fail(
                    "Se produjo un error al preparar o ejecutar el script embebido.\n\n" +
                    ex.Message +
                    BuildPathsSuffix(scriptPath, logPath));
            }
        }

        private static string ResolvePowerShellExe()
        {
            string direct = Environment.ExpandEnvironmentVariables(@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe");
            if (File.Exists(direct))
                return direct;

            return "powershell.exe";
        }

        private static string ExtractReportPath(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
                return null;

            using (var reader = new StringReader(text))
            {
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    const string marker = "__REPORT_PATH__=";
                    if (line.StartsWith(marker, StringComparison.OrdinalIgnoreCase))
                    {
                        return line.Substring(marker.Length).Trim();
                    }
                }
            }

            return null;
        }

        private static string BuildWrappedPowerShellScript(PrivacyConfig config)
        {
            if (config == null)
                throw new ArgumentNullException(nameof(config));

            string originalScript;
            try
            {
                originalScript = Encoding.UTF8.GetString(Convert.FromBase64String(EmbeddedAssets.PowerShellScriptBase64));
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("No se pudo decodificar el script PowerShell embebido desde Base64.", ex);
            }

            if (string.IsNullOrWhiteSpace(originalScript))
                throw new InvalidOperationException("El script PowerShell embebido está vacío después de la decodificación.");

            originalScript = Regex.Replace(
                originalScript,
                @"(?m)^(\s*\$PauseAtEnd\s*=\s*)\$true(\s*(?:#.*)?)$",
                "$1$false$2",
                RegexOptions.IgnoreCase);

            string injectedProfileAssignment =
                "$script:ReportPrivacyProfile = [PSCustomObject]@{ " +
                "Mode = '" + Ps(GetInjectedModeName(config.ModeChoice)) + "'; " +
                "IncludeSHA = " + (config.IncludeSHA ? "$true" : "$false") + "; " +
                "PathMode = '" + Ps(config.PathMode) + "'; " +
                "CommandLineMode = '" + Ps(config.CommandLineMode) + "'; " +
                "IdMode = '" + Ps(config.IdMode) + "'; " +
                "NetworkMode = '" + Ps(config.NetworkMode) + "' }";

            string interactiveAssignmentPattern = @"(?m)^\s*\$script:ReportPrivacyProfile\s*=\s*Get-ReportPrivacyProfile\s*$";
            Match assignmentMatch = Regex.Match(originalScript, interactiveAssignmentPattern, RegexOptions.IgnoreCase);
            if (!assignmentMatch.Success)
            {
                throw new InvalidOperationException(
                    "No se encontró en el script embebido la línea interactiva '$script:ReportPrivacyProfile = Get-ReportPrivacyProfile'. " +
                    "El launcher no puede inyectar el perfil de privacidad de forma segura.");
            }

            string wrappedScript = Regex.Replace(
                originalScript,
                interactiveAssignmentPattern,
                injectedProfileAssignment,
                RegexOptions.IgnoreCase);

            if (wrappedScript.IndexOf("-in @((", StringComparison.Ordinal) >= 0)
            {
                throw new InvalidOperationException(
                    "El wrapper generado detectó una mutación inválida ('-in @((`). Se aborta para evitar ejecutar un script corrupto.");
            }

            var epilogue = new StringBuilder();
            epilogue.AppendLine();
            epilogue.AppendLine("if ($OutFile) { Write-Output ('__REPORT_PATH__=' + $OutFile) }");
            epilogue.AppendLine("if ($script:FatalError) { exit 1 } else { exit 0 }");

            return wrappedScript + Environment.NewLine + epilogue;
        }

        private static string Ps(string value)
        {
            return (value ?? string.Empty).Replace("'", "''");
        }

        private static string GetInjectedModeName(string modeChoice)
        {
            switch (modeChoice)
            {
                case "1":
                    return "Full";
                case "2":
                    return "Review";
                default:
                    return "Custom";
            }
        }

        private static string CreateTempRunDirectory()
        {
            string root = Path.Combine(Path.GetTempPath(), "MSR_Launcher");
            Directory.CreateDirectory(root);

            string dir = Path.Combine(root, DateTime.Now.ToString("yyyyMMdd_HHmmss_fff") + "_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            return dir;
        }

        private static void WriteUtf8BomFile(string path, string content)
        {
            var utf8Bom = new UTF8Encoding(true);
            File.WriteAllText(path, content ?? string.Empty, utf8Bom);
        }

        private static void WriteDiagnosticLog(
            string logPath,
            ProcessStartInfo psi,
            string scriptPath,
            bool timedOut,
            int? exitCode,
            string stdout,
            string stderr)
        {
            var sb = new StringBuilder();
            sb.AppendLine("MASTER SECURITY REVIEW - Launcher debug log");
            sb.AppendLine("Timestamp: " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff"));
            sb.AppendLine("PowerShell: " + (psi != null ? psi.FileName : "(null)"));
            sb.AppendLine("Arguments: " + (psi != null ? psi.Arguments : "(null)"));
            sb.AppendLine("WorkingDirectory: " + (psi != null ? psi.WorkingDirectory : "(null)"));
            sb.AppendLine("ScriptPath: " + (scriptPath ?? "(null)"));
            sb.AppendLine("TimedOut: " + timedOut);
            sb.AppendLine("ExitCode: " + (exitCode.HasValue ? exitCode.Value.ToString() : "(null)"));
            sb.AppendLine();
            sb.AppendLine("===== STDOUT =====");
            sb.AppendLine(stdout ?? string.Empty);
            sb.AppendLine();
            sb.AppendLine("===== STDERR =====");
            sb.AppendLine(stderr ?? string.Empty);

            TryWriteText(logPath, sb.ToString());
        }

        private static void TryWriteText(string path, string content)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(path))
                    return;

                string dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrWhiteSpace(dir))
                    Directory.CreateDirectory(dir);

                File.WriteAllText(path, content ?? string.Empty, new UTF8Encoding(true));
            }
            catch
            {
            }
        }

        private static void TryKillProcess(Process process)
        {
            if (process == null)
                return;

            try
            {
                if (!process.HasExited)
                {
                    process.Kill();
                    process.WaitForExit();
                }
            }
            catch
            {
            }
        }

        private static void TryWaitTasks(Task<string> stdoutTask, Task<string> stderrTask, int millisecondsTimeout)
        {
            try
            {
                Task.WaitAll(new Task[] { stdoutTask, stderrTask }, millisecondsTimeout);
            }
            catch
            {
            }
        }

        private static string GetTaskResult(Task<string> task)
        {
            if (task == null)
                return string.Empty;

            try
            {
                return task.Status == TaskStatus.RanToCompletion ? (task.Result ?? string.Empty) : string.Empty;
            }
            catch
            {
                return string.Empty;
            }
        }

        private static string BuildFailureMessage(
            string header,
            string scriptPath,
            string logPath,
            string stdout,
            string stderr,
            int? exitCode)
        {
            var detail = new StringBuilder();
            detail.AppendLine(header);

            if (exitCode.HasValue)
            {
                detail.AppendLine();
                detail.AppendLine("ExitCode: " + exitCode.Value);
            }

            detail.Append(BuildPathsSuffix(scriptPath, logPath));

            string reportPath = ExtractReportPath(stdout) ?? ExtractReportPath(stderr);
            if (!string.IsNullOrWhiteSpace(reportPath))
            {
                detail.AppendLine();
                detail.AppendLine("Informe detectado:");
                detail.AppendLine(reportPath);
            }

            if (!string.IsNullOrWhiteSpace(stderr))
            {
                detail.AppendLine();
                detail.AppendLine("Detalle técnico (stderr):");
                detail.AppendLine(TrimForDialog(stderr));
            }
            else if (!string.IsNullOrWhiteSpace(stdout))
            {
                detail.AppendLine();
                detail.AppendLine("Salida capturada (stdout):");
                detail.AppendLine(TrimForDialog(stdout));
            }

            return detail.ToString().Trim();
        }

        private static string BuildPathsSuffix(string scriptPath, string logPath)
        {
            var sb = new StringBuilder();

            if (!string.IsNullOrWhiteSpace(scriptPath))
            {
                sb.AppendLine();
                sb.AppendLine("Script generado:");
                sb.AppendLine(scriptPath);
            }

            if (!string.IsNullOrWhiteSpace(logPath))
            {
                sb.AppendLine();
                sb.AppendLine("Log del launcher:");
                sb.AppendLine(logPath);
            }

            return sb.ToString();
        }

        private static string QuoteArg(string value)
        {
            if (value == null)
                return "\"\"";

            return "\"" + value.Replace("\"", "\\\"") + "\"";
        }

        private static string TrimForDialog(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
                return string.Empty;

            string normalized = text.Replace("\r\n", "\n").Replace('\r', '\n').Trim();
            const int maxChars = 3500;
            if (normalized.Length <= maxChars)
                return normalized;

            return normalized.Substring(0, maxChars) + Environment.NewLine + "...[salida recortada]";
        }
    }

    internal sealed class PrivacyConfig
    {
        public string ModeChoice { get; set; }
        public bool IncludeSHA { get; set; }
        public string PathMode { get; set; }
        public string CommandLineMode { get; set; }
        public string IdMode { get; set; }
        public string NetworkMode { get; set; }
    }

    internal sealed class ExecutionResult
    {
        public bool Success { get; private set; }
        public string ReportPath { get; private set; }
        public string ErrorMessage { get; private set; }
        public string ScriptPath { get; private set; }
        public string LogPath { get; private set; }

        public static ExecutionResult Ok(string reportPath, string scriptPath, string logPath)
        {
            return new ExecutionResult
            {
                Success = true,
                ReportPath = reportPath,
                ErrorMessage = string.Empty,
                ScriptPath = scriptPath,
                LogPath = logPath
            };
        }

        public static ExecutionResult Fail(string errorMessage)
        {
            return new ExecutionResult
            {
                Success = false,
                ErrorMessage = errorMessage ?? "Error desconocido."
            };
        }
    }
}
