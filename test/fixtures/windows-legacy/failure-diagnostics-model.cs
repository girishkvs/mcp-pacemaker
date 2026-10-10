using System;
using System.Collections;
using System.ComponentModel;
using System.Threading;
using System.Web.Script.Serialization;

internal sealed class FailureDiagnosticsModel
{
    private static int Main() { return new FailureDiagnosticsModel().Run(); }

    private int Run()
    {
        var native = new LegacyNative();
        var unreadable = new UnreadableDiagnosticError();
        native.TagApi(unreadable, LegacyFailureApi.OpenProcessQuery);
        native.TagFailure(unreadable, LegacyFailureStage.CaptureOpenQuery, 101);
        if (native.FailureDetails(unreadable) != null ||
            unreadable.NativeErrorCode != 5) throw new Exception("Diagnostic fault changed original error");
        var errors = new Exception[4];
        var threads = new Thread[4];
        for (int index = 0; index < threads.Length; index++)
        {
            int worker = index;
            threads[index] = new Thread(() =>
            {
                try
                {
                    var original = new Win32Exception(5);
                    native.TagApi(original, LegacyFailureApi.OpenProcessTerminate);
                    native.TagFailure(original, LegacyFailureStage.CaptureOpenTerminate,
                        200 + worker, 300L + worker, 100 + worker, alive: true, ownerMatched: true);
                    var first = native.FailureDetails(original);
                    native.TagApi(original, LegacyFailureApi.WmiQuery);
                    native.TagFailure(original, LegacyFailureStage.ArgumentQuery, 999, 999);
                    var second = native.FailureDetails(original);
                    if (!ReferenceEquals(first, second) ||
                        second.requestedPid != 200 + worker ||
                        second.creationTime != (300L + worker).ToString(System.Globalization.CultureInfo.InvariantCulture) ||
                        second.api != "OpenProcessTerminate" ||
                        second.substage != "CaptureOpenTerminate" ||
                        original.GetType() != typeof(Win32Exception) ||
                        original.NativeErrorCode != 5) throw new Exception("Per-operation diagnostic association changed");
                }
                catch (Exception error) { errors[worker] = error; }
            });
            threads[index].Start();
        }
        foreach (var thread in threads) thread.Join();
        foreach (var error in errors) if (error != null) throw error;
        Console.WriteLine(new JavaScriptSerializer().Serialize(new {
            diagnosticCollectionFaultPreserved = true, immutablePerOperation = true,
            concurrentOperations = 4, processQueries = 0, modeledIdentities = true
        }));
        return 0;
    }
}

internal sealed class UnreadableDiagnosticError : Win32Exception
{
    internal UnreadableDiagnosticError() : base(5) { }
    public override IDictionary Data { get { throw new InvalidOperationException("test-only unreportable text"); } }
}
