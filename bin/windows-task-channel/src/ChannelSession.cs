using System;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

internal sealed class ChannelSession
{
    internal SessionFact Observe(string expectedSid, int sessionId, string expectedLogonTime)
    {
        if (sessionId <= 0) throw new InvalidOperationException("INTERACTIVE_SESSION_REQUIRED");
        var before = Snapshot(sessionId);
        var user = Text(sessionId, 5);
        var domain = Text(sessionId, 7);
        if (string.IsNullOrWhiteSpace(user) ||
            string.IsNullOrWhiteSpace(domain) ||
            user.IndexOf('\\') >= 0 ||
            domain.IndexOf('\\') >= 0) throw new InvalidOperationException("SESSION_ACCOUNT_UNAVAILABLE");
        var sid = Resolve(domain + "\\" + user);
        var secondUser = Text(sessionId, 5);
        var secondDomain = Text(sessionId, 7);
        var after = Snapshot(sessionId);
        if (!string.Equals(user, secondUser, StringComparison.Ordinal) ||
            !string.Equals(domain, secondDomain, StringComparison.Ordinal))
            throw new InvalidOperationException("SESSION_ACCOUNT_CHANGED");
        MatchName(before.shortUser, user, 20);
        MatchName(after.shortUser, user, 20);
        MatchName(before.shortDomain, domain, 17);
        MatchName(after.shortDomain, domain, 17);
        return Validate(before, after, sid, expectedSid, sessionId, expectedLogonTime);
    }

    private void MatchName(string snapshot, string full, int bound)
    {
        bool matches = !string.IsNullOrEmpty(snapshot) &&
            snapshot.Length <= bound &&
            (snapshot.Length == bound
                ? full.StartsWith(snapshot, StringComparison.OrdinalIgnoreCase)
                : string.Equals(snapshot, full, StringComparison.OrdinalIgnoreCase));
        if (!matches) throw new InvalidOperationException("SESSION_ACCOUNT_CHANGED");
    }

    internal SessionFact Validate(SessionSnapshot before, SessionSnapshot after, string resolvedSid,
        string expectedSid, int sessionId, string expectedLogonTime)
    {
        if (sessionId <= 0 ||
            before.sessionId != sessionId ||
            after.sessionId != sessionId) throw new InvalidOperationException("SESSION_ID_MISMATCH");
        bool loggedOn = (before.state == 0 || before.state == 4) &&
            (after.state == 0 || after.state == 4);
        if (!loggedOn ||
            before.logonTime <= 0 ||
            after.logonTime <= 0) throw new InvalidOperationException("SESSION_NOT_LOGGED_ON");
        bool stable = before.logonTime == after.logonTime &&
            before.state == after.state &&
            before.shortUser == after.shortUser &&
            before.shortDomain == after.shortDomain;
        if (!stable) throw new InvalidOperationException("SESSION_GENERATION_CHANGED");
        if (string.IsNullOrEmpty(resolvedSid) ||
            resolvedSid != expectedSid) throw new InvalidOperationException("SESSION_OWNER_MISMATCH");
        var logon = after.logonTime.ToString(CultureInfo.InvariantCulture);
        if (expectedLogonTime != null &&
            expectedLogonTime != logon) throw new InvalidOperationException("SESSION_GENERATION_CHANGED");
        return new SessionFact
        {
            sessionId = sessionId, ownerSid = resolvedSid, state = after.state == 0 ? "active" : "disconnected",
            logonTime = logon, observedAt = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture),
            source = "wts-account-sid-snapshot", atomicRunExBinding = false
        };
    }

    private T Query<T>(int sessionId, int kind, Func<IntPtr, uint, T> read)
    {
        IntPtr buffer;
        uint length;
        bool succeeded = WtsApi.WTSQuerySessionInformationW(IntPtr.Zero, sessionId, kind, out buffer, out length);
        int error = Marshal.GetLastWin32Error();
        try
        {
            RequireQuery(succeeded, error);
            if (buffer == IntPtr.Zero ||
                length < 2 ||
                length > 65536) throw new InvalidOperationException("SESSION_QUERY_BOUNDS");
            return read(buffer, length);
        }
        finally { if (buffer != IntPtr.Zero) WtsApi.WTSFreeMemory(buffer); }
    }

    private void RequireQuery(bool succeeded, int error)
    {
        if (!succeeded) throw new InvalidOperationException("SESSION_QUERY_FAILED_" + error.ToString(CultureInfo.InvariantCulture));
    }

    private void RequireUser(int use)
    {
        if (use != 1) throw new InvalidOperationException("SESSION_ACCOUNT_NOT_USER");
    }

    private string Text(int sessionId, int kind)
    {
        return Query(sessionId, kind, (buffer, length) =>
        {
            if ((length & 1) != 0) throw new InvalidOperationException("SESSION_TEXT_BOUNDS");
            int count = checked((int)length / 2);
            var text = Marshal.PtrToStringUni(buffer, count);
            if (text[count - 1] != '\0') throw new InvalidOperationException("SESSION_TEXT_UNTERMINATED");
            text = text.Substring(0, count - 1);
            if (text.IndexOf('\0') >= 0) throw new InvalidOperationException("SESSION_TEXT_AMBIGUOUS");
            return text;
        });
    }

    private SessionSnapshot Snapshot(int sessionId)
    {
        return Query(sessionId, 25, (buffer, length) =>
        {
            if (length < Marshal.SizeOf(typeof(WtsApi.Information)))
                throw new InvalidOperationException("SESSION_GENERATION_UNAVAILABLE");
            var info = (WtsApi.Information)Marshal.PtrToStructure(buffer, typeof(WtsApi.Information));
            if (info.level != 1) throw new InvalidOperationException("SESSION_GENERATION_UNSUPPORTED");
            return new SessionSnapshot
            {
                sessionId = checked((int)info.data.sessionId), state = info.data.state,
                logonTime = info.data.logonTime, shortUser = info.data.user, shortDomain = info.data.domain
            };
        });
    }

    private string Resolve(string account)
    {
        uint sidSize = 0, domainSize = 0;
        int use;
        WtsApi.LookupAccountNameW(null, account, IntPtr.Zero, ref sidSize, null, ref domainSize, out use);
        int error = Marshal.GetLastWin32Error();
        if (error != 122 ||
            sidSize < 8 ||
            sidSize > 68 ||
            domainSize < 1 ||
            domainSize > 32768) throw new InvalidOperationException("SESSION_SID_LOOKUP_FAILED_" + error.ToString(CultureInfo.InvariantCulture));
        var sid = Marshal.AllocHGlobal(checked((int)sidSize));
        try
        {
            var domain = new StringBuilder(checked((int)domainSize));
            if (!WtsApi.LookupAccountNameW(null, account, sid, ref sidSize, domain, ref domainSize, out use))
                throw new InvalidOperationException("SESSION_SID_LOOKUP_FAILED_" + Marshal.GetLastWin32Error().ToString(CultureInfo.InvariantCulture));
            RequireUser(use);
            return new SecurityIdentifier(sid).Value;
        }
        finally { Marshal.FreeHGlobal(sid); }
    }
}

internal sealed class SessionSnapshot
{
    public int sessionId { get; set; }
    public int state { get; set; }
    public long logonTime { get; set; }
    public string shortUser { get; set; }
    public string shortDomain { get; set; }
}

internal sealed class SessionFact
{
    public int sessionId { get; set; }
    public string ownerSid { get; set; }
    public string state { get; set; }
    public string logonTime { get; set; }
    public string observedAt { get; set; }
    public string source { get; set; }
    public bool atomicRunExBinding { get; set; }
}

internal static class WtsApi
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct LevelOne
    {
        internal uint sessionId;
        internal int state, flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 33)] internal string station;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 21)] internal string user;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 18)] internal string domain;
        internal long logonTime, connectTime, disconnectTime, lastInputTime, currentTime;
        internal uint incomingBytes, outgoingBytes, incomingFrames, outgoingFrames, incomingCompressed, outgoingCompressed;
    }
    [StructLayout(LayoutKind.Sequential)]
    internal struct Information
    {
        internal uint level;
        internal LevelOne data;
    }
    [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool WTSQuerySessionInformationW(IntPtr server, int sessionId, int kind,
        out IntPtr buffer, out uint length);
    [DllImport("wtsapi32.dll")]
    internal static extern void WTSFreeMemory(IntPtr buffer);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool LookupAccountNameW(string system, string account, IntPtr sid, ref uint sidLength,
        StringBuilder domain, ref uint domainLength, out int use);
}
