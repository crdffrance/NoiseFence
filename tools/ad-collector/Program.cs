using System.Diagnostics;
using System.DirectoryServices.Protocols;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace NoiseFence.AdCollector;

internal static class Program
{
    internal static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 32,
    };
    public static int Main(string[] args)
    {
        try
        {
            if (args.Length == 1 && args[0] == "self-test") { Fixtures.Run(); return 0; }
            if (args.Length == 2 && args[0] == "fixture") { Fixtures.Write(args[1]); return 0; }
            if (!OperatingSystem.IsWindows()) throw new InvalidOperationException("Live collection requires Windows.");
            if (args.Length == 2 && args[0] == "public-key")
            {
                using var cert = Signing.Certificate(args[1]);
                using var key = cert.GetECDsaPublicKey() ?? throw new InvalidOperationException("P-256 certificate required.");
                Console.WriteLine(JsonSerializer.Serialize(new { public_key = Convert.ToBase64String(Signing.Public(key)), key_id = Signing.KeyId(key) }, Json));
                return 0;
            }
            if (args.Length != 3 || args[0] != "collect") throw new InvalidOperationException("Usage: collect PROFILE.json NEW-EXPORT.json | public-key THUMBPRINT | self-test");
            var info = new FileInfo(args[1]);
            if (info.Length > 8192) throw new InvalidOperationException("Profile too large.");
            var profile = JsonSerializer.Deserialize<Profile>(File.ReadAllBytes(args[1]), Json) ?? throw new InvalidOperationException("Profile required.");
            profile.Validate();
            using var certificate = Signing.Certificate(profile.CertificateThumbprint);
            using var signing = certificate.GetECDsaPrivateKey() ?? throw new InvalidOperationException("Accessible ECDSA private key required.");
            _ = Signing.Public(signing);
            using var collector = new Collector(profile);
            var payload = collector.Collect();
            Signing.WriteNew(args[2], Signing.Envelope(signing, payload));
            Console.WriteLine("Signed directory export created. Import within 15 minutes; review before activation.");
            return 0;
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // Directory values, LDAP diagnostics and certificate details never enter logs.
            Console.Error.WriteLine("AD collection refused. Check the documented prerequisites, profile, permissions and limits. No partial export is usable.");
            return 1;
        }
    }
}
internal sealed record Profile(string SourceId, string DomainDns, string DomainGuid, string Controller, string CertificateThumbprint)
{
    internal void Validate()
    {
        Require.That(SourceId.Length is > 0 and <= 100 && !SourceId.Any(char.IsControl));
        Require.That(Names.Host(DomainDns) && Names.Host(Controller) && Names.Guid(DomainGuid));
        Require.That(Regex.IsMatch(CertificateThumbprint, "\\A[0-9A-Fa-f]{40}\\z", RegexOptions.CultureInvariant));
    }
}
internal static class Require { internal static void That(bool ok) { if (!ok) throw new InvalidOperationException("Collector invariant failed."); } }
internal static class Names
{
    internal static bool Host(string v) => v.Length <= 253 && v.Contains('.') && v.Split('.').All(l => l.Length is > 0 and <= 63 && l[0] != '-' && l[^1] != '-' && l.All(c => c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-'));
    internal static bool Guid(string v) => System.Guid.TryParseExact(v, "D", out var guid) && guid != System.Guid.Empty && guid.ToString("D") == v;
    internal static string Sid(byte[] v)
    {
        Require.That(v.Length >= 8 && v[0] == 1 && v.Length == 8 + 4 * v[1] && v[1] is > 0 and <= 15);
        ulong authority = 0; for (var i = 2; i < 8; i++) authority = (authority << 8) | v[i];
        var s = $"S-1-{authority}";
        for (var i = 0; i < v[1]; i++) s += "-" + System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(v.AsSpan(8 + i * 4, 4)).ToString(CultureInfo.InvariantCulture);
        return s;
    }
    internal static string PrimarySid(string sid, uint rid) { Require.That(rid > 0 && sid.StartsWith("S-1-5-21-", StringComparison.Ordinal)); return sid[..(sid.LastIndexOf('-') + 1)] + rid.ToString(CultureInfo.InvariantCulture); }
}
internal sealed record User(string Id, string DisplayName, bool? Enabled, string? Mail, string[] ProxyAddresses);
internal sealed record Group(string Id, string DisplayName, string? Mail, string[] ProxyAddresses);
internal sealed record Member(string Kind, string Id);
internal sealed record Membership(string Group, Member Member);
internal sealed record Counts(int People, int Groups, int Memberships);
internal sealed record Payload(string CollectionId, string SourceId, string DomainDns, string DomainGuid, string Controller, long StartedAt, long CompletedAt, bool Complete, int Requests, int Pages, Counts Counts, User[] People, Group[] Groups, Membership[] Memberships, SortedDictionary<string, int> ExcludedMembers);
internal sealed record Envelope(string Protocol, string Id, string KeyId, string Payload, string Signature);
internal static class Signing
{
    internal static readonly byte[] Prefix = Encoding.UTF8.GetBytes("noisefence:ad-export-1\0");
    internal static byte[] Public(ECDsa key)
    {
        var p = key.ExportParameters(false);
        Require.That(p.Curve.Oid.Value == "1.2.840.10045.3.1.7" && p.Q.X?.Length == 32 && p.Q.Y?.Length == 32);
        return [4, .. p.Q.X!, .. p.Q.Y!];
    }
    internal static string KeyId(ECDsa key) => Convert.ToHexStringLower(SHA256.HashData(Public(key)));
    internal static Envelope Envelope(ECDsa key, Payload payload)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(payload, Program.Json);
        Require.That(bytes.Length <= 16 * 1024 * 1024);
        var signature = key.SignData([.. Prefix, .. bytes], HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return new("noisefence-ad-export-1", payload.CollectionId, KeyId(key), Convert.ToBase64String(bytes), Convert.ToBase64String(signature));
    }
    internal static void WriteNew<T>(string path, T data)
    {
        // The operator supplies an ACL-protected directory. Create-new prevents
        // replacing an older export; move is atomic on the same filesystem.
        var full = Path.GetFullPath(path);
        var temporary = full + "." + Guid.NewGuid().ToString("N") + ".partial";
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            { JsonSerializer.Serialize(stream, data, Program.Json); stream.Flush(true); }
            File.Move(temporary, full, false);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
    internal static X509Certificate2 Certificate(string thumbprint)
    {
        Require.That(Regex.IsMatch(thumbprint, "\\A[0-9A-Fa-f]{40}\\z", RegexOptions.CultureInvariant));
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        var matches = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
        Require.That(matches.Count == 1);
        var cert = matches[0];
        Require.That(cert.NotBefore.ToUniversalTime() <= DateTime.UtcNow && cert.NotAfter.ToUniversalTime() > DateTime.UtcNow);
        return cert;
    }
}
internal sealed class Collector : IDisposable
{
    private readonly Profile profile;
    private readonly LdapConnection ldap;
    private readonly Stopwatch elapsed = Stopwatch.StartNew();
    private readonly long started = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    private int requests, pages;
    private long bytes;
    private const int MaxEdges = 100_000;
    private readonly Dictionary<string, (string Kind, string Id)> objects = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> groupSids = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> userPrimaries = new(StringComparer.Ordinal);
    private readonly SortedDictionary<string, int> exclusions = new(StringComparer.Ordinal);
    internal Collector(Profile profile)
    {
        this.profile = profile;
        // Explicit Kerberos: Negotiate/NTLM and Basic are never used. The Windows
        // service identity supplies credentials. OS trust/hostname checks apply.
        ldap = new LdapConnection(new LdapDirectoryIdentifier(profile.Controller, 636, true, false), CredentialCache.DefaultNetworkCredentials, AuthType.Kerberos);
        ldap.Timeout = TimeSpan.FromSeconds(10);
        ldap.SessionOptions.ProtocolVersion = 3;
        ldap.SessionOptions.SecureSocketLayer = true;
        ldap.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
        ldap.SessionOptions.AutoReconnect = false;
        ldap.Bind();
    }
    public void Dispose() => ldap.Dispose();
    private void Budget() { Require.That(elapsed.Elapsed.TotalSeconds <= 300 && requests < 4096 && bytes <= 64 * 1024 * 1024); }
    private SearchResponse Search(SearchRequest request)
    {
        Budget(); requests++;
        request.TimeLimit = TimeSpan.FromSeconds(Math.Min(10, Math.Max(1, 300 - elapsed.Elapsed.TotalSeconds)));
        var response = (SearchResponse)ldap.SendRequest(request);
        Require.That(response.ResultCode == ResultCode.Success && response.References.Count == 0);
        foreach (SearchResultEntry entry in response.Entries)
        {
            bytes += Encoding.UTF8.GetByteCount(entry.DistinguishedName);
            foreach (DirectoryAttribute attribute in entry.Attributes.Values)
            {
                bytes += Encoding.UTF8.GetByteCount(attribute.Name);
                foreach (var value in attribute) bytes += value is byte[] b ? b.Length : Encoding.UTF8.GetByteCount((string)value);
            }
        }
        Require.That(bytes <= 64 * 1024 * 1024 && elapsed.Elapsed.TotalSeconds <= 300);
        return response;
    }
    private SearchResultEntry One(string dn, params string[] attrs)
    {
        var response = Search(new SearchRequest(dn, "(objectClass=*)", SearchScope.Base, attrs));
        Require.That(response.Entries.Count == 1); return response.Entries[0];
    }
    private List<SearchResultEntry> All(string root, string filter, int maximum, params string[] attrs)
    {
        var output = new List<SearchResultEntry>(); var cursors = new HashSet<string>(StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        byte[] cookie = [];
        do
        {
            var request = new SearchRequest(root, filter, SearchScope.Subtree, attrs);
            request.Controls.Add(new PageResultRequestControl(100) { Cookie = cookie, IsCritical = true });
            var response = Search(request); pages++;
            Require.That(response.Entries.Count <= 100);
            var controls = response.Controls.OfType<PageResultResponseControl>().ToArray();
            Require.That(controls.Length == 1);
            foreach (SearchResultEntry entry in response.Entries)
            {
                Require.That(output.Count < maximum && seen.Add(entry.DistinguishedName));
                // No silently truncated aliases or other multivalue attributes.
                foreach (string name in entry.Attributes.AttributeNames) Require.That(!name.Contains(";range=", StringComparison.OrdinalIgnoreCase) || name.StartsWith("member;range=", StringComparison.OrdinalIgnoreCase));
                output.Add(entry);
            }
            cookie = controls[0].Cookie;
            Require.That(cookie.Length <= 65536 && (cookie.Length == 0 || cursors.Add(Convert.ToHexString(SHA256.HashData(cookie)))));
        } while (cookie.Length != 0);
        return output;
    }
    internal static string[] Values(SearchResultEntry entry, string name) => entry.Attributes[name]?.GetValues(typeof(string)).Cast<string>().ToArray() ?? [];
    private static string? Optional(SearchResultEntry entry, string name) { var v = Values(entry, name); Require.That(v.Length <= 1); return v.FirstOrDefault(); }
    private static string Required(SearchResultEntry entry, string name) { var v = Optional(entry, name); Require.That(!string.IsNullOrEmpty(v)); return v!; }
    private static byte[] Binary(SearchResultEntry entry, string name)
    {
        var a = entry.Attributes[name]; Require.That(a is not null && a.Count == 1); return (byte[])a![0];
    }
    private static string Id(SearchResultEntry entry) { var b = Binary(entry, "objectGUID"); Require.That(b.Length == 16); var id = new Guid(b).ToString("D"); Require.That(Names.Guid(id)); return id; }
    private static string Display(SearchResultEntry entry)
    {
        var value = Optional(entry, "displayName");
        if (string.IsNullOrWhiteSpace(value)) value = string.Join(" ", new[] { Optional(entry, "givenName"), Optional(entry, "sn") }.Where(v => !string.IsNullOrWhiteSpace(v)));
        if (string.IsNullOrWhiteSpace(value)) value = Optional(entry, "cn");
        Require.That(!string.IsNullOrWhiteSpace(value) && value.Length <= 500 && !value.Any(char.IsControl)); return value!;
    }
    private static string[] Proxies(SearchResultEntry entry) { var p = Values(entry, "proxyAddresses"); Require.That(p.Length <= 128 && p.All(v => v.Length <= 1024 && !v.Any(char.IsControl))); return p; }
    // Validate AD's range continuity. No assumed MaxValRange; an asterisk ends a
    // range only when the server supplies it. Same LDAP connection throughout.
    internal static (int Next, bool Done) Range(string name, int expected, int count)
    {
        var m = Regex.Match(name, "\\Amember;range=([0-9]+)-([0-9]+|\\*)\\z", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        Require.That(m.Success && int.TryParse(m.Groups[1].Value, out var low) && low == expected);
        if (m.Groups[2].Value == "*") return (checked(expected + count), true);
        Require.That(int.TryParse(m.Groups[2].Value, out var high) && high >= expected && high < MaxEdges && high - expected + 1 == count && count > 0);
        return (checked(expected + count), false);
    }
    private string[] Members(SearchResultEntry original)
    {
        var dn = original.DistinguishedName; var version = Required(original, "uSNChanged");
        var list = new List<string>(); var expected = 0;
        while (true)
        {
            var entry = One(dn, $"member;range={expected}-*", "uSNChanged", "objectGUID");
            Require.That(Id(entry) == Id(original) && Required(entry, "uSNChanged") == version);
            var names = entry.Attributes.AttributeNames.Cast<string>().Where(n => n.StartsWith("member;range=", StringComparison.OrdinalIgnoreCase)).ToArray();
            if (names.Length == 0)
            {
                // The non-ranged form is valid only for the initial full value;
                // a missing later range is never accepted as completion.
                Require.That(expected == 0); list.AddRange(Values(entry, "member")); Require.That(list.Count <= MaxEdges); break;
            }
            Require.That(names.Length == 1 && Values(entry, "member").Length == 0);
            var values = Values(entry, names[0]); var range = Range(names[0], expected, values.Length);
            Require.That(range.Next <= MaxEdges); list.AddRange(values); expected = range.Next; if (range.Done) break;
        }
        Require.That(list.Distinct(StringComparer.OrdinalIgnoreCase).Count() == list.Count);
        return list.ToArray();
    }
    internal Payload Collect()
    {
        var root = One("", "defaultNamingContext", "dnsHostName");
        Require.That(Required(root, "dnsHostName").Equals(profile.Controller, StringComparison.OrdinalIgnoreCase));
        var dn = Required(root, "defaultNamingContext");
        Require.That(dn.Equals(string.Join(",", profile.DomainDns.Split('.').Select(v => "DC=" + v)), StringComparison.OrdinalIgnoreCase));
        Require.That(Id(One(dn, "objectGUID")) == profile.DomainGuid);
        var userEntries = All(dn, "(&(objectCategory=person)(objectClass=user))", 20_000, "objectGUID", "displayName", "givenName", "sn", "cn", "userAccountControl", "mail", "proxyAddresses", "objectSid", "primaryGroupID");
        var groupEntries = All(dn, "(objectClass=group)", 5_000, "objectGUID", "displayName", "cn", "mail", "proxyAddresses", "objectSid", "uSNChanged");
        var users = new List<User>(); var groups = new List<Group>(); var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in userEntries)
        {
            var id = Id(entry); Require.That(ids.Add(id) && objects.TryAdd(entry.DistinguishedName, ("person", id)));
            bool? enabled = null; var uac = Optional(entry, "userAccountControl"); if (uac is not null) { Require.That(uint.TryParse(uac, NumberStyles.None, CultureInfo.InvariantCulture, out var n)); enabled = (n & 2) == 0; }
            users.Add(new(id, Display(entry), enabled, Optional(entry, "mail"), Proxies(entry)));
            Require.That(uint.TryParse(Required(entry, "primaryGroupID"), NumberStyles.None, CultureInfo.InvariantCulture, out var rid));
            userPrimaries.Add(id, Names.PrimarySid(Names.Sid(Binary(entry, "objectSid")), rid));
        }
        foreach (var entry in groupEntries)
        {
            var id = Id(entry); Require.That(ids.Add(id) && objects.TryAdd(entry.DistinguishedName, ("group", id)));
            groupSids.Add(Names.Sid(Binary(entry, "objectSid")), id);
            groups.Add(new(id, Display(entry), Optional(entry, "mail"), Proxies(entry)));
        }
        var edges = new HashSet<Membership>();
        foreach (var entry in groupEntries)
        {
            var group = Id(entry);
            foreach (var memberDn in Members(entry))
            {
                if (objects.TryGetValue(memberDn, out var member)) { edges.Add(new(group, new(member.Kind, member.Id))); }
                else
                {
                    var excluded = One(memberDn, "objectClass"); var classes = Values(excluded, "objectClass");
                    var kind = classes.Contains("computer", StringComparer.OrdinalIgnoreCase) ? "device" : classes.Contains("foreignSecurityPrincipal", StringComparer.OrdinalIgnoreCase) ? "external_membership" : null;
                    Require.That(kind is not null); exclusions[kind!] = exclusions.GetValueOrDefault(kind!) + 1;
                }
                Require.That(edges.Count <= MaxEdges && exclusions.Values.Sum() <= MaxEdges);
            }
        }
        foreach (var (user, sid) in userPrimaries) { Require.That(groupSids.TryGetValue(sid, out var group)); edges.Add(new(group!, new("person", user))); Require.That(edges.Count <= MaxEdges); }
        Budget(); Require.That(Id(One(dn, "objectGUID")) == profile.DomainGuid);
        return new(Guid.NewGuid().ToString("D"), profile.SourceId, profile.DomainDns, profile.DomainGuid, profile.Controller, started, DateTimeOffset.UtcNow.ToUnixTimeSeconds(), true, requests, pages, new(users.Count, groups.Count, edges.Count), users.ToArray(), groups.ToArray(), edges.OrderBy(e => e.Group, StringComparer.Ordinal).ThenBy(e => e.Member.Kind, StringComparer.Ordinal).ThenBy(e => e.Member.Id, StringComparer.Ordinal).ToArray(), exclusions);
    }
}
