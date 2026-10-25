using System.Security.Cryptography;
using System.Text.Json;
namespace NoiseFence.AdCollector;

internal static class Fixtures
{
    private const string Id = "2905b910-836f-4466-bba4-ae2a00661c74";
    internal static Payload Payload() => new(Id, "internal-ad", "corp.example", Id, "dc1.corp.example", 1792929590, 1792929600, true, 6, 2, new(1, 1, 1), [new("ea68885a-80df-434b-8aa4-de28dd5f46ed", "Alice Example", true, "alice@example.com", ["SMTP:alice@example.com"])], [new("9905b910-836f-4466-bba4-ae2a00661c74", "Accounts", null, [])], [new("9905b910-836f-4466-bba4-ae2a00661c74", new("person", "ea68885a-80df-434b-8aa4-de28dd5f46ed"))], new());
    internal static void Write(string path)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Signing.WriteNew(path, new { public_key = Convert.ToBase64String(Signing.Public(key)), envelope = Signing.Envelope(key, Payload()) });
    }
    private static void Reject(Action action) { try { action(); } catch (InvalidOperationException) { return; } throw new InvalidOperationException("Negative fixture accepted."); }
    internal static void Run()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256); var envelope = Signing.Envelope(key, Payload());
        var data = Convert.FromBase64String(envelope.Payload); var sig = Convert.FromBase64String(envelope.Signature);
        Require.That(sig.Length == 64 && key.VerifyData(Signing.Prefix.Concat(data).ToArray(), sig, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        data[0] ^= 1; Require.That(!key.VerifyData(Signing.Prefix.Concat(data).ToArray(), sig, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        using var wrong = ECDsa.Create(ECCurve.NamedCurves.nistP384); Reject(() => Signing.Public(wrong));
        Require.That(Collector.Range("member;range=0-1499", 0, 1500) == (1500, false));
        Require.That(Collector.Range("member;range=1500-*", 1500, 3) == (1503, true));
        Reject(() => Collector.Range("member;range=1-100", 0, 100));
        Reject(() => Collector.Range("member;range=1500-1499", 1500, 0));
        Reject(() => Collector.Range("member;range=0-1500", 0, 1500));
        Reject(() => Collector.Range("member;range=0-100000", 0, 100001));
        Reject(() => Collector.Range("member", 0, 0));
        Require.That(Names.PrimarySid("S-1-5-21-1-2-3-999", 513) == "S-1-5-21-1-2-3-513");
        Require.That(Names.Sid([1, 1, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0]) == "S-1-5-32");
        Reject(() => Names.Sid([1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0]));
        var profile = new Profile("ad", "corp.example", Id, "dc1.corp.example", new string('A', 40)); profile.Validate();
        Reject(() => (profile with { Controller = "https://dc1.corp.example" }).Validate());
        Reject(() => (profile with { DomainDns = "corp.example,OU=other" }).Validate());
        Reject(() => (profile with { DomainGuid = "00000000-0000-0000-0000-000000000000" }).Validate());
        Reject(() => (profile with { CertificateThumbprint = "A" }).Validate());
        Console.WriteLine("AD collector offline fixtures passed (signature, tamper, curve, ranges, SID, primary group, profile). No LDAP connection made.");
    }
}
