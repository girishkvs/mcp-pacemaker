using System;
using System.Collections.Generic;
using System.Globalization;
using System.Reflection;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Web.Script.Serialization;

internal sealed class BoundsModel
{
    private readonly JavaScriptSerializer json = new JavaScriptSerializer { MaxJsonLength = 262144, RecursionLimit = 20 };
    private readonly LegacyNative native = new LegacyNative();
    private readonly string sid = WindowsIdentity.GetCurrent().User.Value;

    private static int Main()
    {
        return new BoundsModel().Run();
    }

    private int Run()
    {
        var results = new List<object>();
        foreach (int total in new[] { 64, 65, 511, 512, 513 })
            results.Add(Check("members-" + total, Plan(total, 0), total <= 512));
        foreach (int total in new[] { 511, 512, 513 })
            results.Add(Check("combined-" + total, Plan(2, total - 2), total <= 512));
        var unicode = Plan(300, 0);
        foreach (var identity in unicode.observed) identity.imagePath = @"C:\" + new string('\u4e2d', 200) + ".exe";
        Seal(unicode);
        results.Add(Check("utf8-plan-overflow", unicode, false));
        var duplicate = Plan(4, 0);
        duplicate.observed[1].pid = duplicate.observed[0].pid;
        Seal(duplicate);
        results.Add(Check("duplicate-generation-id", duplicate, false));
        var cache = CheckImages();
        Console.WriteLine(json.Serialize(new { model = true, processQueries = 0, processMutations = 0, results, cache }));
        return 0;
    }

    private object Check(string name, Plan plan, bool expected)
    {
        bool accepted;
        var reason = "";
        try
        {
            typeof(LegacyProcessBroker).GetMethod("ValidatePlan", BindingFlags.NonPublic | BindingFlags.Instance)
                .Invoke(new LegacyProcessBroker(), new object[] { plan });
            accepted = true;
        }
        catch (TargetInvocationException error) { accepted = false; reason = error.InnerException.Message; }
        if (accepted != expected) throw new InvalidOperationException("Bounds model mismatch: " + name);
        return new { name, accepted, reason, total = plan.observed.Length + plan.excluded.Length + 2,
            utf8Bytes = Encoding.UTF8.GetByteCount(json.Serialize(plan)) };
    }

    private Identity Identity(int id)
    {
        return new Identity { pid = id, creationTime = "134360000000000000",
            parentPid = 1, parentCreationTime = "134360000000000000",
            ownerSid = sid, imagePath = @"C:\owned-model\worker.exe",
            imageSha256 = new string('a', 64), argvSha256 = new string('b', 64) };
    }

    private Plan Plan(int held, int excluded)
    {
        var observed = new List<Identity>();
        for (int index = 2; index < held; index++) observed.Add(Identity(index + 1));
        var excludedRows = new List<ExcludedIdentity>();
        for (int index = 0; index < excluded; index++)
            excludedRows.Add(new ExcludedIdentity { pid = held + index + 1, creationTime = "134359999999999000",
                parentPid = 1, parentCreationTime = "134360000000000000", reason = "predates-held-parent" });
        var plan = new Plan { protocol = 1, kind = "legacy-observed-process-set", port = 1,
            root = @"C:\owned-model", ownerSid = sid, treeCompleteness = "unproven",
            roots = new Roots { supervisor = Identity(1), bridge = Identity(2) },
            observed = observed.ToArray(), excluded = excludedRows.ToArray(),
            scope = "Model only; IDs are never queried." };
        Seal(plan);
        return plan;
    }

    private void Seal(Plan plan)
    {
        plan.observedSetSha256 = native.Hash(Encoding.UTF8.GetBytes(json.Serialize(plan.observed)));
        plan.planSha256 = null;
        plan.planSha256 = native.Hash(Encoding.UTF8.GetBytes(json.Serialize(plan)));
    }

    private object CheckImages()
    {
        var root = Path.Combine(Path.GetTempPath(), "legacy-image-cache-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var first = Path.Combine(root, "first.bin");
            var alias = Path.Combine(root, "alias.bin");
            File.WriteAllText(first, "owned-cache-original");
            if (!ModelApi.CreateHardLinkW(alias, first, IntPtr.Zero)) throw new InvalidOperationException("Owned hardlink setup failed");
            var oldDigest = "";
            bool writeRefused = false;
            bool deleteRefused = false;
            using (var cache = new LegacyImageCache(() => { }))
            {
                oldDigest = cache.Hash(first);
                if (cache.Hash(alias) != oldDigest ||
                    cache.Count != 1) throw new InvalidOperationException("File identity alias was not shared");
                try { File.WriteAllText(alias, "unwanted write"); } catch (IOException) { writeRefused = true; }
                try { File.Delete(first); } catch (IOException) { deleteRefused = true; }
                if (!writeRefused ||
                    !deleteRefused) throw new InvalidOperationException("Pinned file allowed write/delete");
            }
            File.WriteAllText(first, "owned-cache-replacement");
            using (var fresh = new LegacyImageCache(() => { }))
                if (fresh.Hash(first) == oldDigest) throw new InvalidOperationException("Prior phase digest reused");
            using (var cache = new LegacyImageCache(() => { }))
            {
                for (int index = 0; index < 65; index++)
                {
                    var path = Path.Combine(root, "distinct-" + index + ".bin");
                    File.WriteAllText(path, "owned-" + index);
                    if (index < 64) cache.Hash(path);
                    else RequireImageRefusal(cache, path);
                }
            }
            var large = Path.Combine(root, "too-large.bin");
            using (var stream = new FileStream(large, FileMode.CreateNew)) stream.SetLength(256L * 1024 * 1024 + 1);
            using (var cache = new LegacyImageCache(() => { })) RequireImageRefusal(cache, large);
            using (var cache = new LegacyImageCache(() => { }))
            {
                // Model only the already-hashed byte counter; no 512 MiB read is needed.
                typeof(LegacyImageCache).GetProperty("Bytes", BindingFlags.Instance | BindingFlags.NonPublic)
                    .GetSetMethod(true).Invoke(cache, new object[] { 512L * 1024 * 1024 });
                RequireImageRefusal(cache, first);
            }
            return new { hardlinkShared = true, writeRefused, deleteRefused,
                freshPhaseChangedDigest = true, distinct65Refused = true, file256MiBPlusOneRefused = true,
                total512MiBCounterModelRefused = true };
        }
        finally { Directory.Delete(root, true); }
    }

    private void RequireImageRefusal(LegacyImageCache cache, string path)
    {
        try { cache.Hash(path); }
        catch (InvalidOperationException error)
        {
            if (error.Message == "Image hash bound") return;
            throw;
        }
        throw new InvalidOperationException("Image bound was not enforced");
    }
}

internal static class ModelApi
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CreateHardLinkW(string link, string existing, IntPtr security);
}
