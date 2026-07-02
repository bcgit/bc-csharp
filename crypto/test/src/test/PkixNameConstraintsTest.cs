using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tests
{
    /// <summary>
    /// Test class for {@link PkixNameConstraintValidator}.
    /// The field testXYZ is the name to test.
    /// The field testXYZIsConstraint must be tested if it is permitted and excluded.
    /// The field testXYZIsNotConstraint must be tested if it is not permitted and
    /// not excluded.
    /// Furthermore there are tests for the intersection and union of test names.
    /// </summary>
    [TestFixture]
    public class PkixNameConstraintsTest
    {
        private readonly string testEmail = "test@abc.test.com";

        private readonly string[] testEmailIsConstraint = { "test@abc.test.com", "abc.test.com", ".test.com" };

        private readonly string[] testEmailIsNotConstraint = { ".abc.test.com", "www.test.com", "test1@abc.test.com", "bc.test.com" };

        private readonly string[] email1 = {
            "test@test.com", "test@test.com", "test@test.com", "test@abc.test.com",
            "test@test.com", "test@test.com", ".test.com", ".test.com",
            ".test.com", ".test.com", "test.com", "abc.test.com",
            "abc.test1.com", "test.com", "test.com", ".test.com" };

        private readonly string[] email2 = {
            "test@test.abc.com", "test@test.com", ".test.com", ".test.com",
            "test.com", "test1.com", "test@test.com", ".test.com",
            ".test1.com", "test.com", "test.com", ".test.com", ".test.com",
            "test1.com", ".test.com", "abc.test.com" };

        private readonly string[] emailintersect = {
            null, "test@test.com", null, "test@abc.test.com", "test@test.com", null,
            null, ".test.com", null, null, "test.com", "abc.test.com", null,
            null, null, "abc.test.com" };

        private readonly string[][] emailunion = new string[16][] {
            new string[] { "test@test.com", "test@test.abc.com" },
            new string[] { "test@test.com" },
            new string[] { "test@test.com", ".test.com" },
            new string[] { ".test.com" },
            new string[] { "test.com" },
            new string[] { "test@test.com", "test1.com" },
            new string[] { ".test.com", "test@test.com" },
            new string[] { ".test.com" },
            new string[] { ".test.com", ".test1.com" },
            new string[] { ".test.com", "test.com" },
            new string[] { "test.com" },
            new string[] { ".test.com" },
            new string[] { ".test.com", "abc.test1.com" },
            new string[] { "test1.com", "test.com" },
            new string[] { ".test.com", "test.com" },
            new string[] { ".test.com" } };

        private readonly string[] dn1 = { "O=test org, OU=test org unit, CN=John Doe" };

        private readonly string[] dn2 = { "O=test org, OU=test org unit" };

        private readonly string[][] dnUnion = new string[1][] {
            new string[] { "O=test org, OU=test org unit" } };

        private readonly string[] dnIntersection = { "O=test org, OU=test org unit, CN=John Doe" };

        // Note: In BC text conversion is ISO format - IETF starts at the back.
        private readonly string testDN = "O=test org, OU=test org unit, CN=John Doe";

        private readonly string[] testDNIsConstraint =
        {
            "O=test org, OU=test org unit",
            "O=test org, OU=test org unit, CN=John Doe",
        };

        private readonly string[] testDNIsNotConstraint =
        {
            "O=test org, OU=test org unit, CN=John Doe2",
            "O=test org, OU=test org unit2",
            "O=test org, OU=test org unit, CN=John Doe, L=USA"
        };

        private readonly string testDNS = "abc.test.com";

        private readonly string[] testDNSIsConstraint = { "test.com", "abc.test.com", "test.com" };

        private readonly string[] testDNSIsNotConstraint = { "wwww.test.com", "ww.test.com", "www.test.com" };

        private readonly string[] dns1 = { "www.test.de", "www.test1.de", "www.test.de" };

        private readonly string[] dns2 = { "test.de", "www.test.de", "www.test.de" };

        private readonly string[] dnsintersect = { "www.test.de", null, "www.test.de" };

        private readonly string[][] dnsunion = new string[3][] {
            new string[] { "test.de" },
            new string[] { "www.test1.de", "www.test.de" },
            new string[] { "www.test.de" } };

        private readonly string testURI = "http://karsten:password@abc.test.com:8080";

        private readonly string[] testURIIsConstraint = { "abc.test.com", ".test.com" };

        private readonly string[] testURIIsNotConstraint = { "xyz.test.com", ".abc.test.com" };

        private readonly string[] uri1 = { "www.test.de", ".test.de", "test1.de", ".test.de" };

        private readonly string[] uri2 = { "test.de", "www.test.de", "test1.de", ".test.de" };

        private readonly string[] uriintersect = { null, "www.test.de", "test1.de", ".test.de" };

        private readonly string[][] uriunion = new string[4][] {
            new string[] { "www.test.de", "test.de" },
            new string[] { ".test.de" },
            new string[] { "test1.de" },
            new string[] { ".test.de" } };

        private readonly byte[] testIP = { (byte)192, (byte)168, 1, 2 };

        private readonly byte[][] testIPIsConstraint = new byte[2][] {
            new byte[] { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0 },
            new byte[] { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 4 } };

        private readonly byte[][] testIPIsNotConstraint = new byte[2][] {
            new byte[] { (byte) 192, (byte) 168, 3, 1, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 2 },
            new byte[] { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 3 } };

        private readonly byte[][] ip1 = new byte[3][] {
            new byte[] { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                        (byte) 0xFE, (byte) 0xFF },
            new byte[] { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                        (byte) 0xFF, (byte) 0xFF },
            new byte[] { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                        (byte) 0xFF, (byte) 0x00 } };

        private readonly byte[][] ip2 = new byte[3][] {
            new byte[] { (byte) 192, (byte) 168, 0, 1, (byte) 0xFF, (byte) 0xFF,
                        (byte) 0xFC, 3 },
            new byte[] { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                        (byte) 0xFF, (byte) 0xFF },
            new byte[] { (byte) 192, (byte) 168, 0, 1, (byte) 0xFF, (byte) 0xFF,
                        (byte) 0xFF, (byte) 0x00 } };

        private readonly byte[][] ipintersect = new byte[3][] {
            new byte[] { (byte) 192, (byte) 168, 0, 1, (byte) 0xFF, (byte) 0xFF,
                        (byte) 0xFE, (byte) 0xFF },
            new byte[] { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                        (byte) 0xFF, (byte) 0xFF }, null };

        private readonly byte[][][] ipunion = new byte[3][][] {
            new byte[2][] {
                            new byte[] { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                                            (byte) 0xFE, (byte) 0xFF },
                            new byte[] { (byte) 192, (byte) 168, 0, 1, (byte) 0xFF, (byte) 0xFF,
                                            (byte) 0xFC, 3 } },
            new byte[1][] {
                            new byte[] { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                                            (byte) 0xFF, (byte) 0xFF } },
            new byte[2][] {
                            new byte[] { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                                            (byte) 0xFF, (byte) 0x00 },
                            new byte[] { (byte) 192, (byte) 168, 0, 1, (byte) 0xFF, (byte) 0xFF,
                                            (byte) 0xFF, (byte) 0x00 } } };

        [Test]
        public void Basic()
        {
            TestConstraints(GeneralName.Rfc822Name, testEmail,
                testEmailIsConstraint, testEmailIsNotConstraint, email1, email2,
                emailunion, emailintersect);
            TestConstraints(GeneralName.DnsName, testDNS, testDNSIsConstraint,
                testDNSIsNotConstraint, dns1, dns2, dnsunion, dnsintersect);
            TestConstraints(GeneralName.DirectoryName, testDN, testDNIsConstraint,
                testDNIsNotConstraint, dn1, dn2, dnUnion, dnIntersection);
            TestConstraints(GeneralName.UniformResourceIdentifier, testURI,
                testURIIsConstraint, testURIIsNotConstraint, uri1, uri2, uriunion,
                uriintersect);
            TestConstraints(GeneralName.IPAddress, testIP, testIPIsConstraint,
                testIPIsNotConstraint, ip1, ip2, ipunion, ipintersect);

            PkixNameConstraintValidator constraintValidator = new PkixNameConstraintValidator();
            constraintValidator.IntersectPermittedSubtree(new GeneralSubtree(
                new GeneralName(GeneralName.DirectoryName,
                    new X509Name(true, "ou=permittedSubtree1, o=Test Certificates 2011, c=US"))));
            constraintValidator.CheckPermittedName(
                new GeneralName(GeneralName.DirectoryName,
                    new X509Name(true, "cn=Valid DN nameConstraints EE Certificate Test1, ou=permittedSubtree1, o=Test Certificates 2011, c=US")));

            GeneralName name = new GeneralName(GeneralName.OtherName, new OtherName(new DerObjectIdentifier("1.1"), DerNull.Instance));
            GeneralSubtree subtree = new GeneralSubtree(name);

            PkixNameConstraintValidator validator = new PkixNameConstraintValidator();
            validator.IntersectPermittedSubtree(subtree);

            name = new GeneralName(GeneralName.OtherName, new OtherName(new DerObjectIdentifier("1.1"), DerNull.Instance));
            subtree = new GeneralSubtree(name);

            validator = new PkixNameConstraintValidator();
            validator.IntersectPermittedSubtree(subtree);
            validator.AddExcludedSubtree(subtree);

            try
            {
                validator.CheckExcludedName(name);
            }
            catch (PkixNameConstraintValidatorException e)
            {
                Assert.AreEqual("OtherName is from an excluded subtree.", e.Message);
            }

            try
            {
                validator.CheckPermittedName(name);
            }
            catch (PkixNameConstraintValidatorException e)
            {
                Assert.Fail(e.Message);
            }
        }

        /// <summary>
        /// RFC 1034 sec. 3.1 root-label trailing dot. A trailing '.' is legal in an rfc822Name, a dNSName
        /// (RFC 5280 sec. 4.2.1.6) and a uniformResourceIdentifier host, and must be canonicalized away
        /// uniformly across all three so it can't misalign the per-label compare and let a name escape an
        /// excluded subtree.
        /// </summary>
        [Test]
        public void TrailingDotBypass()
        {
            // rfc822Name: a trailing dot on the mail host must not escape the excluded bank.com subtree.
            Assert.True(IsExcluded(EmailName("bank.com"), EmailName("ceo@bank.com.")),
                "trailing-dot email must be caught by the excluded bank.com subtree");

            // dNSName: exact and subdomain forms, including a dot-prefixed constraint.
            Assert.True(IsExcluded(DnsName("example.com"), DnsName("example.com.")),
                "exact host with a trailing dot must be caught");
            Assert.True(IsExcluded(DnsName("example.com"), DnsName("foo.example.com.")),
                "subdomain with a trailing dot must be caught");
            Assert.True(IsExcluded(DnsName(".example.com"), DnsName("foo.example.com.")),
                "subdomain with a trailing dot must be caught by a dot-prefixed constraint");
            Assert.False(IsExcluded(DnsName("example.com"), DnsName("notexample.com.")),
                "a sibling domain must not be caught");

            // uniformResourceIdentifier: the host trailing dot is stripped like the dNSName path.
            Assert.True(
                IsExcluded(UriName("competitor.example"), UriName("https://competitor.example./")),
                "trailing-dot URI host must be caught by the excluded competitor.example subtree");
        }

        /// <summary>
        /// directoryName constraints must match as an INITIAL PREFIX of the subject (RFC 5280 sec.
        /// 4.2.1.10 / 7.1), not as a subsequence at an arbitrary offset. Prepending an RDN ahead of the
        /// permitted sequence must not satisfy the constraint.
        /// </summary>
        [Test]
        public void DirectoryNamePrefixBypass()
        {
            GeneralName permittedDN = new GeneralName(GeneralName.DirectoryName,
                new X509Name(reverse: true, "ou=permittedSubtree1, o=Test Certificates 2011, c=US"));
            GeneralName prefixSubject = new GeneralName(GeneralName.DirectoryName,
                new X509Name(reverse: true, "cn=Valid DN nameConstraints EE Certificate Test1, ou=permittedSubtree1, o=Test Certificates 2011, c=US"));
            GeneralName prependedSubject = new GeneralName(GeneralName.DirectoryName,
                new X509Name(reverse: true, "cn=Valid DN nameConstraints EE Certificate Test1, ou=permittedSubtree1, o=Test Certificates 2011, c=US, o=Injected"));

            Assert.True(IsPermitted(permittedDN, prefixSubject), "prefix subject must be permitted");
            Assert.False(IsPermitted(permittedDN, prependedSubject),
                "subject with an RDN prepended before the permitted sequence must NOT be permitted");
        }

        /// <summary>
        /// A directoryName whose sequence elements are not RDN-shaped fails at the boundary parse
        /// (fail-closed) when DN constraints are present - even where the malformed element lies beyond
        /// the compared prefix and so was previously never examined; with no DN constraints in play it
        /// is not examined at all.
        /// </summary>
        [Test]
        public void MalformedDnRejectedWhenConstrained()
        {
            // A valid RDN followed by an element that is not one (RDNSequence elements must be SETs).
            Asn1Sequence validDn = Asn1Sequence.GetInstance(new X509Name("O=Org").ToAsn1Object());
            Asn1Sequence malformed = new DerSequence(validDn[0], new DerIA5String("junk"));

            PkixNameConstraintValidator excluding = new PkixNameConstraintValidator();
            excluding.AddExcludedSubtree(new GeneralSubtree(DirectoryName("O=Other")));
            Assert.Throws<ArgumentException>(() => excluding.CheckExcludedDN(malformed),
                "a malformed DN must be rejected at parse, not silently pass the excluded check");

            PkixNameConstraintValidator permitting = new PkixNameConstraintValidator();
            permitting.IntersectPermittedSubtree(new GeneralSubtree(DirectoryName("O=Other")));
            Assert.Throws<ArgumentException>(() => permitting.CheckPermittedDN(malformed),
                "a malformed DN must be rejected at parse in the permitted check");

            PkixNameConstraintValidator fresh = new PkixNameConstraintValidator();
            fresh.CheckPermittedDN(malformed);
            fresh.CheckExcludedDN(malformed);
        }

        /// <summary>
        /// uniformResourceIdentifier host-extraction edge cases (RFC 3986 sec. 3.2 authority). These
        /// exercise <c>ExtractHostFromURL</c> indirectly: a bracketed IPv6 literal (whose ':' separators
        /// must not be read as a port delimiter), userinfo stripping, and the path/query/fragment
        /// terminator being applied BEFORE the userinfo '@' so an '@' in the path or fragment can't be
        /// mistaken for a userinfo delimiter and swap in an attacker-chosen host.
        /// </summary>
        [Test]
        public void UriHostExtractionBypass()
        {
            // Bracketed IPv6 host: the ':' inside the literal must not truncate at a phantom port, however
            // the port/userinfo are dressed up around it.
            Assert.True(IsExcluded(UriName("2001:db8::1"), UriName("https://[2001:db8::1]:8443/x")),
                "bracketed IPv6 host with a port must be caught by the excluded 2001:db8::1 subtree");
            Assert.True(IsExcluded(UriName("2001:db8::1"), UriName("https://[2001:db8::1]/x")),
                "bracketed IPv6 host without a port must be caught");
            Assert.True(IsExcluded(UriName("2001:db8::1"), UriName("https://user:pw@[2001:db8::1]:8443/x")),
                "bracketed IPv6 host behind userinfo must be caught");

            // An '@' after the path/query/fragment terminator must NOT be read as userinfo; otherwise the
            // host would become the attacker-chosen authority after the '@' and escape the constraint.
            Assert.True(
                IsExcluded(UriName("competitor.example"),
                    UriName("https://competitor.example?u=x@evil.example")),
                "'@' in the query must not be treated as userinfo");
            Assert.True(
                IsExcluded(UriName("competitor.example"),
                    UriName("https://competitor.example#@evil.example")),
                "'@' in the fragment must not be treated as userinfo");

            // A genuine userinfo '@' before the host is still stripped.
            Assert.True(IsExcluded(UriName("host.example"), UriName("https://user@host.example/")),
                "userinfo before the host must be stripped");

            // Sanity: an unrelated host is not caught (extraction isn't over-matching).
            Assert.False(IsExcluded(UriName("competitor.example"), UriName("https://safe.example/")),
                "an unrelated URI host must not be caught");
        }

        /// <summary>
        /// IPv4-mapped IPv6 (RFC 4291 sec. 2.5.5.2, <c>::ffff:0:0/96</c>) iPAddress normalization. A SAN
        /// that encodes an IPv4 address in the 16-byte mapped form must not slip past an 8-byte IPv4
        /// constraint (or vice versa) via the address-family length mismatch; and a constraint whose mask
        /// is narrower than /96 is a genuine IPv6 range that must not be collapsed to IPv4.
        /// </summary>
        [Test]
        public void IPv4MappedAddressBypass()
        {
            // 192.0.2.0/24 as an 8-byte IPv4 constraint (address || mask).
            byte[] ipv4Cidr24 = Bytes(192, 0, 2, 0, 0xFF, 0xFF, 0xFF, 0x00);

            // The same /24 as a 32-byte IPv4-mapped IPv6 constraint (all-ones across the /96 prefix).
            byte[] mappedCidr24 = Bytes(
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 192, 0, 2, 0,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00);

            // mapped SAN vs IPv4 constraint: caught (16-byte SAN normalizes to 4-byte 192.0.2.5).
            Assert.True(IsExcluded(IPName(ipv4Cidr24), IPName(IPv4Mapped(192, 0, 2, 5))),
                "IPv4-mapped SAN must be caught by the excluded IPv4 /24 constraint");

            // IPv4 SAN vs mapped constraint: caught (32-byte constraint normalizes to the /24).
            Assert.True(IsExcluded(IPName(mappedCidr24), IPName(Bytes(192, 0, 2, 5))),
                "IPv4 SAN must be caught by the excluded IPv4-mapped /24 constraint");

            // Out-of-range mapped SAN must NOT be caught (normalization isn't over-matching).
            Assert.False(IsExcluded(IPName(ipv4Cidr24), IPName(IPv4Mapped(198, 51, 100, 5))),
                "a mapped SAN outside the /24 must not be caught");

            // A mapped-address constraint with a mask narrower than /96 (here /64) is a genuine IPv6 range
            // and must NOT be collapsed to IPv4, so an IPv4 SAN must not match it.
            byte[] mappedNarrowMask = Bytes(
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 192, 0, 2, 0,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0);
            Assert.False(IsExcluded(IPName(mappedNarrowMask), IPName(Bytes(192, 0, 2, 5))),
                "an IPv6-range constraint (mask < /96) must not be collapsed to match an IPv4 SAN");
        }

        /// <summary>
        /// Set-algebra (Intersect*/Union*) canonicalisation guards. When repeated NameConstraints
        /// extensions along a chain are combined, the pairwise subtree intersection/union must treat
        /// RFC 1034 trailing-dot variants and IPv4-mapped IPv6 forms (RFC 4291 sec. 2.5.5.2) as the
        /// names they denote, not as distinct strings/bytes.
        /// </summary>
        [Test]
        public void SetAlgebraTrailingDotDns()
        {
            // Intersecting dot and non-dot forms of the same domain must not empty the permitted set.
            Assert.True(
                IsPermittedAfterIntersect(DnsName("example.com."), DnsName("example.com"),
                    DnsName("foo.example.com")),
                "intersection of trailing-dot and plain forms must keep permitting subdomains");

            // The union of both forms must still catch a subdomain.
            Assert.True(
                IsExcludedAfterUnion(DnsName("example.com"), DnsName("example.com."),
                    DnsName("foo.example.com")),
                "union of trailing-dot and plain forms must keep excluding subdomains");
        }

        /// <summary>See <see cref="SetAlgebraTrailingDotDns"/>; the rfc822Name domain form.</summary>
        [Test]
        public void SetAlgebraTrailingDotEmailDomainForm()
        {
            Assert.True(
                IsPermittedAfterIntersect(EmailName(".test.com."), EmailName(".test.com"),
                    EmailName("user@abc.test.com")),
                "intersection of trailing-dot and plain domain-form email constraints must not be empty");
        }

        /// <summary>
        /// Union outcomes must be invariant under trailing-dot variation: whatever form(s) the union
        /// stores, matching must still catch the plain name.
        /// </summary>
        [Test]
        public void SetAlgebraTrailingDotUnionOutcomes()
        {
            Assert.True(
                IsExcludedAfterUnion(EmailName("test.com"), EmailName("test.com."),
                    EmailName("user@test.com")),
                "union of trailing-dot and plain host-form email constraints must keep excluding");

            Assert.True(
                IsExcludedAfterUnion(UriName("test.de"), UriName("test.de."),
                    UriName("http://test.de/abc")),
                "union of trailing-dot and plain URI host constraints must keep excluding");
        }

        /// <summary>
        /// The empty-name escape for an emptied permitted URI set applies to the raw name, NOT the
        /// extracted host: a non-empty URI whose authority is empty must still be rejected.
        /// </summary>
        [Test]
        public void UriEmptyNameEscapeUsesRawString()
        {
            PkixNameConstraintValidator validator = new PkixNameConstraintValidator();
            validator.IntersectEmptyPermittedSubtree(GeneralName.UniformResourceIdentifier);

            // An empty uniformResourceIdentifier name is tolerated against an emptied permitted set.
            validator.CheckPermittedName(UriName(""));

            Assert.Throws<PkixNameConstraintValidatorException>(
                () => validator.CheckPermittedName(UriName("http://")),
                "a non-empty URI with an empty host must not use the empty-name escape");
        }

        /// <summary>
        /// An IP range intersection can itself land on the IPv4-mapped ::ffff:0:0/96 block even when
        /// neither operand does. The stored intersection must still be treated as (canonicalised to)
        /// its IPv4 form when matching a 4-byte IPv4 SAN.
        /// </summary>
        [Test]
        public void SetAlgebraIpIntersectionMappedResult()
        {
            // Two 32-byte (IPv6) constraints on ::ffff:192.0.2.0, each with a mask that leaves a hole
            // in the /96 prefix (mask byte 11) so that NEITHER is itself collapsible to IPv4 form.
            byte[] mappedHoleFE = Bytes(
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 192, 0, 2, 0,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0x00);
            byte[] mappedHole01 = Bytes(
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 192, 0, 2, 0,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0xFF, 0xFF, 0xFF, 0x00);

            // Their intersection ORs the masks back to a full /96 prefix: ::ffff:192.0.2.0/120, i.e.
            // the IPv4-mapped form of 192.0.2.0/24.
            Assert.True(
                IsPermittedAfterIntersect(IPName(mappedHoleFE), IPName(mappedHole01),
                    IPName(Bytes(192, 0, 2, 5))),
                "an intersection collapsing to an IPv4-mapped range must match the IPv4 form");
            Assert.False(
                IsPermittedAfterIntersect(IPName(mappedHoleFE), IPName(mappedHole01),
                    IPName(Bytes(198, 51, 100, 5))),
                "an IPv4 SAN outside the intersected range must not match");
        }

        /// <summary>A fresh validator constrains nothing: both checks pass for every name family.</summary>
        [Test]
        public void UnconstrainedValidatorChecksPass()
        {
            PkixNameConstraintValidator validator = new PkixNameConstraintValidator();
            GeneralName[] names = {
                EmailName("user@test.com"),
                DnsName("foo.example.com"),
                DirectoryName("O=test org, CN=John Doe"),
                UriName("http://test.de/abc"),
                IPName(Bytes(192, 0, 2, 5)),
                new GeneralName(GeneralName.OtherName,
                    new OtherName(new DerObjectIdentifier("1.1"), DerNull.Instance)),
            };
            foreach (GeneralName name in names)
            {
                validator.CheckPermittedName(name);
                validator.CheckExcludedName(name);
            }
        }

        /// <summary>
        /// With no IP constraints in play, a structurally invalid iPAddress SAN passes both checks:
        /// name-constraint processing only judges names against constraints that exist.
        /// </summary>
        [Test]
        public void UnconstrainedMalformedIpNameTolerated()
        {
            PkixNameConstraintValidator validator = new PkixNameConstraintValidator();
            validator.CheckPermittedName(IPName(Bytes(1, 2, 3, 4, 5)));
            validator.CheckExcludedName(IPName(Bytes(1, 2, 3, 4, 5)));
            validator.CheckPermittedName(IPName(Bytes()));
            validator.CheckExcludedName(IPName(Bytes()));
        }

        /// <summary>Host comparisons are case-insensitive across all three string-host families.</summary>
        [Test]
        public void CaseInsensitiveMatching()
        {
            Assert.True(IsExcluded(EmailName("TEST.com"), EmailName("user@test.com")),
                "an upper-cased host-form email constraint must still catch the lower-case mailbox");
            Assert.True(IsExcluded(DnsName("EXAMPLE.com"), DnsName("foo.example.com")),
                "an upper-cased dNSName constraint must still catch a lower-case subdomain");
            Assert.True(IsExcluded(UriName("HOST.example"), UriName("https://host.example/")),
                "an upper-cased URI constraint must still catch the lower-case host");
        }

        /// <summary>
        /// Validators whose dNSName constraint sets denote the same names (up to case and the RFC 1034
        /// trailing dot) compare equal: constraints are stored in canonical form with value equality.
        /// </summary>
        [Test]
        public void ValidatorEqualityCanonicalDns()
        {
            PkixNameConstraintValidator a = new PkixNameConstraintValidator();
            a.AddExcludedSubtree(new GeneralSubtree(DnsName("Example.COM.")));

            PkixNameConstraintValidator b = new PkixNameConstraintValidator();
            b.AddExcludedSubtree(new GeneralSubtree(DnsName("example.com")));

            Assert.AreEqual(a, b, "excluded dNSName sets differing by case/trailing dot must compare equal");
            Assert.AreEqual(a.GetHashCode(), b.GetHashCode(), "hash codes must agree for equal validators");
        }

        /// <summary>
        /// Intersecting host-form email constraints that differ only by the RFC 1034 trailing dot must
        /// not produce an empty permitted set (they denote the same host).
        /// </summary>
        [Test]
        public void SetAlgebraTrailingDotEmailHostForm()
        {
            Assert.True(
                IsPermittedAfterIntersect(EmailName("test.com."), EmailName("test.com"),
                    EmailName("user@test.com")),
                "intersection of trailing-dot and plain host-form email constraints must not be empty");
        }

        /// <summary>See <see cref="SetAlgebraTrailingDotEmailHostForm"/>; the particular-mailbox form.</summary>
        [Test]
        public void SetAlgebraTrailingDotEmailMailboxForm()
        {
            Assert.True(
                IsPermittedAfterIntersect(EmailName("u@test.com."), EmailName("u@test.com"),
                    EmailName("u@test.com")),
                "intersection of trailing-dot and plain mailbox constraints must not be empty");
        }

        /// <summary>
        /// As <see cref="ValidatorEqualityCanonicalDns"/> for rfc822Name, including dedup on the union
        /// path: adding a case/dot variant of an already-excluded constraint must not grow the set.
        /// </summary>
        [Test]
        public void ValidatorEqualityCanonicalEmail()
        {
            PkixNameConstraintValidator a = new PkixNameConstraintValidator();
            a.AddExcludedSubtree(new GeneralSubtree(EmailName("test.com")));
            a.AddExcludedSubtree(new GeneralSubtree(EmailName("TEST.COM.")));

            PkixNameConstraintValidator b = new PkixNameConstraintValidator();
            b.AddExcludedSubtree(new GeneralSubtree(EmailName("test.com")));

            Assert.AreEqual(a, b, "excluded email sets differing by case/trailing dot must compare equal");
            Assert.AreEqual(a.GetHashCode(), b.GetHashCode(), "hash codes must agree for equal validators");
        }

        /// <summary>
        /// Intersecting URI host constraints that differ only by the RFC 1034 trailing dot must not
        /// produce an empty permitted set (they denote the same host).
        /// </summary>
        [Test]
        public void SetAlgebraTrailingDotUriHostForm()
        {
            Assert.True(
                IsPermittedAfterIntersect(UriName("test.de."), UriName("test.de"),
                    UriName("http://test.de/abc")),
                "intersection of trailing-dot and plain URI host constraints must not be empty");
        }

        /// <summary>As <see cref="ValidatorEqualityCanonicalDns"/> for uniformResourceIdentifier.</summary>
        [Test]
        public void ValidatorEqualityCanonicalUri()
        {
            PkixNameConstraintValidator a = new PkixNameConstraintValidator();
            a.AddExcludedSubtree(new GeneralSubtree(UriName("Test.DE.")));

            PkixNameConstraintValidator b = new PkixNameConstraintValidator();
            b.AddExcludedSubtree(new GeneralSubtree(UriName("test.de")));

            Assert.AreEqual(a, b, "excluded URI sets differing by case/trailing dot must compare equal");
            Assert.AreEqual(a.GetHashCode(), b.GetHashCode(), "hash codes must agree for equal validators");
        }

        /// <summary>
        /// The legacy "@host" rfc822Name constraint form matches a mailbox on exactly that host - not
        /// subdomains - and canonicalises like the other forms.
        /// </summary>
        [Test]
        public void EmailAtHostConstraintForm()
        {
            Assert.True(IsPermitted(EmailName("@abc.test.com"), EmailName("test@abc.test.com")),
                "an @host constraint must permit a mailbox on that exact host");
            Assert.True(IsExcluded(EmailName("@abc.test.com"), EmailName("test@abc.test.com")),
                "an @host constraint must exclude a mailbox on that exact host");
            Assert.False(IsExcluded(EmailName("@test.com"), EmailName("test@abc.test.com")),
                "an @host constraint must not match subdomain hosts");

            // RFC 1034 trailing-dot canonicalisation applies to the @host form too.
            Assert.True(IsExcluded(EmailName("@abc.test.com."), EmailName("test@abc.test.com")),
                "a trailing-dot @host constraint must still match");

            // Set algebra groups @host with the particular-address forms.
            Assert.True(
                IsPermittedAfterIntersect(EmailName("@test.com"), EmailName("@test.com"),
                    EmailName("u@test.com")),
                "intersecting identical @host constraints must not empty the permitted set");
        }

        /// <summary>
        /// A uniformResourceIdentifier constraint containing '@' can never match: the tested name's host
        /// is extracted with the userinfo stripped (RFC 3986 sec. 3.2), so it cannot contain '@', and the
        /// host comparison is against the whole constraint string. Pin that such constraints stay inert
        /// in matching (they participate only in the subtree set algebra).
        /// </summary>
        [Test]
        public void UriAtConstraintFormsAreInert()
        {
            Assert.False(IsExcluded(UriName("user@test.de"), UriName("http://user@test.de/x")),
                "a mailbox-shaped URI constraint must not match the host after its '@'");
            Assert.False(IsPermitted(UriName("user@test.de"), UriName("http://test.de/x")),
                "a mailbox-shaped URI constraint must not permit the host after its '@'");

            Assert.False(IsExcluded(UriName("@test.de"), UriName("http://user@test.de/x")),
                "an @host-shaped URI constraint must not match the host after its '@'");
            Assert.False(IsPermitted(UriName("@test.de"), UriName("http://test.de/x")),
                "an @host-shaped URI constraint must not permit the host after its '@'");
        }

        /// <summary>
        /// Intersecting the same IPv4 range expressed as an 8-byte IPv4 constraint and as a 32-byte
        /// IPv4-mapped IPv6 constraint (RFC 4291 sec. 2.5.5.2) must not produce an empty permitted set.
        /// </summary>
        [Test]
        public void SetAlgebraMappedIpIntersection()
        {
            byte[] ipv4Cidr24 = Bytes(192, 0, 2, 0, 0xFF, 0xFF, 0xFF, 0x00);
            byte[] mappedCidr24 = Bytes(
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 192, 0, 2, 0,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00);

            Assert.True(
                IsPermittedAfterIntersect(IPName(mappedCidr24), IPName(ipv4Cidr24), IPName(Bytes(192, 0, 2, 5))),
                "mapped and plain IPv4 forms of the same range must intersect");
            Assert.False(
                IsPermittedAfterIntersect(IPName(mappedCidr24), IPName(ipv4Cidr24),
                    IPName(Bytes(198, 51, 100, 5))),
                "an IPv4 SAN outside the intersected range must not match");
        }

        /// <summary>
        /// As <see cref="ValidatorEqualityCanonicalDns"/> for iPAddress: mapped and plain forms of the
        /// same range compare equal and dedupe within one extension.
        /// </summary>
        [Test]
        public void ValidatorEqualityCanonicalIp()
        {
            byte[] ipv4Cidr24 = Bytes(192, 0, 2, 0, 0xFF, 0xFF, 0xFF, 0x00);
            byte[] mappedCidr24 = Bytes(
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 192, 0, 2, 0,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00);

            PkixNameConstraintValidator a = new PkixNameConstraintValidator();
            a.AddExcludedSubtree(new GeneralSubtree(IPName(mappedCidr24)));

            PkixNameConstraintValidator b = new PkixNameConstraintValidator();
            b.AddExcludedSubtree(new GeneralSubtree(IPName(ipv4Cidr24)));

            Assert.AreEqual(a, b, "mapped and plain forms of the same excluded range must compare equal");
            Assert.AreEqual(a.GetHashCode(), b.GetHashCode(), "hash codes must agree for equal validators");

            PkixNameConstraintValidator c = new PkixNameConstraintValidator();
            c.IntersectPermittedSubtree(new DerSequence(
                new GeneralSubtree(IPName(mappedCidr24)), new GeneralSubtree(IPName(ipv4Cidr24))));

            PkixNameConstraintValidator d = new PkixNameConstraintValidator();
            d.IntersectPermittedSubtree(new GeneralSubtree(IPName(ipv4Cidr24)));

            Assert.AreEqual(c, d, "duplicate mapped/plain permitted constraints must dedupe");
        }

        /// <summary>Structurally invalid iPAddress constraints are rejected (fail-closed) at registration.</summary>
        [Test]
        public void MalformedIpConstraintRejected()
        {
            byte[][] malformed = {
                Bytes(),
                Bytes(1, 2, 3, 4, 0xFF, 0xFF, 0xFF),
                Bytes(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16),
            };
            foreach (byte[] octets in malformed)
            {
                PkixNameConstraintValidator validator = new PkixNameConstraintValidator();
                Assert.Throws<PkixNameConstraintValidatorException>(
                    () => validator.AddExcludedSubtree(new GeneralSubtree(IPName(octets))),
                    "excluding a malformed iPAddress constraint must be rejected");
                Assert.Throws<PkixNameConstraintValidatorException>(
                    () => validator.IntersectPermittedSubtree(new GeneralSubtree(IPName(octets))),
                    "permitting a malformed iPAddress constraint must be rejected");
            }
        }

        /// <summary>
        /// With IP constraints present, a structurally invalid iPAddress SAN is rejected (fail-closed)
        /// instead of silently failing to match - which, for an excluded subtree, was fail-open.
        /// </summary>
        [Test]
        public void MalformedIpNameRejectedWhenConstrained()
        {
            byte[] ipv4Cidr24 = Bytes(192, 0, 2, 0, 0xFF, 0xFF, 0xFF, 0x00);
            byte[] malformed = Bytes(1, 2, 3, 4, 5);

            PkixNameConstraintValidator excluding = new PkixNameConstraintValidator();
            excluding.AddExcludedSubtree(new GeneralSubtree(IPName(ipv4Cidr24)));
            Assert.Throws<PkixNameConstraintValidatorException>(
                () => excluding.CheckExcludedName(IPName(malformed)),
                "a malformed iPAddress SAN must not escape a non-empty excluded set");

            PkixNameConstraintValidator permitting = new PkixNameConstraintValidator();
            permitting.IntersectPermittedSubtree(new GeneralSubtree(IPName(ipv4Cidr24)));
            Assert.Throws<PkixNameConstraintValidatorException>(
                () => permitting.CheckPermittedName(IPName(malformed)),
                "a malformed iPAddress SAN must not satisfy a permitted set");
        }

        /// <summary>The empty-iPAddress escape past an emptied permitted set is gone (fail-closed).</summary>
        [Test]
        public void EmptyIpNameNoLongerEscapes()
        {
            PkixNameConstraintValidator validator = new PkixNameConstraintValidator();
            validator.IntersectEmptyPermittedSubtree(GeneralName.IPAddress);
            Assert.Throws<PkixNameConstraintValidatorException>(
                () => validator.CheckPermittedName(IPName(Bytes())),
                "an empty iPAddress name must not use the empty-name escape");
        }

        /// <summary>
        /// The combined CheckName/CheckDN/CheckEmail methods apply the permitted and excluded checks
        /// together, converting the name once.
        /// </summary>
        [Test]
        public void CombinedChecks()
        {
            PkixNameConstraintValidator validator = new PkixNameConstraintValidator();
            validator.IntersectPermittedSubtree(new GeneralSubtree(DnsName("example.com")));
            validator.AddExcludedSubtree(new GeneralSubtree(DnsName("foo.example.com")));

            validator.CheckName(DnsName("bar.example.com"));
            Assert.Throws<PkixNameConstraintValidatorException>(
                () => validator.CheckName(DnsName("foo.example.com")),
                "an excluded name must fail the combined check");
            Assert.Throws<PkixNameConstraintValidatorException>(
                () => validator.CheckName(DnsName("other.com")),
                "a non-permitted name must fail the combined check");

            PkixNameConstraintValidator dnValidator = new PkixNameConstraintValidator();
            dnValidator.IntersectPermittedSubtree(new GeneralSubtree(DirectoryName("O=Org")));
            dnValidator.CheckDN(new X509Name("O=Org, CN=x"));
            Assert.Throws<PkixNameConstraintValidatorException>(
                () => dnValidator.CheckDN(new X509Name("O=Other, CN=x")),
                "a non-permitted DN must fail the combined check");

            PkixNameConstraintValidator emailValidator = new PkixNameConstraintValidator();
            emailValidator.AddExcludedSubtree(new GeneralSubtree(EmailName("bank.com")));
            emailValidator.CheckEmail("user@safe.com");
            Assert.Throws<PkixNameConstraintValidatorException>(
                () => emailValidator.CheckEmail("ceo@bank.com"),
                "an excluded email must fail the combined check");
        }

        /// <summary>GSMA SGP.22 v2.5 relaxed directoryName name-constraint matching.</summary>
        /// <remarks>
        /// Gated behind <seealso cref="Properties.X509Sgp22NameConstraints"/>, off by default. With the flag set,
        /// additional subject attributes are tolerated and serialNumber is matched with a StartsWith comparison
        /// wherever it appears; with the flag clear the strict RFC 5280 matching is unchanged.
        /// </remarks>
        [Test]
        public void Sgp22NameConstraints()
        {
            GeneralName subtreeExtra = DirectoryName("O=VALID, serialNumber=89034011");
            GeneralName subjectExtra = DirectoryName(
                "C=ES, O=VALID, CN=VALID EUICC CD, OU=VALID, serialNumber=89034011026140000000000000001332");

            GeneralName subtreeSnFirst = DirectoryName("serialNumber=89034011, O=VALID");
            GeneralName subjectSnFirst = DirectoryName("serialNumber=89034011026140000000000000001332, O=VALID");

            // default (flag off): RFC 5280 strict prefix matching rejects both SGP.22 cases
            Assert.False(IsPermitted(subtreeExtra, subjectExtra),
                "SGP.22 extra-attributes should be rejected by default");
            Assert.False(IsPermitted(subtreeSnFirst, subjectSnFirst),
                "SGP.22 leading serialNumber should be rejected by default");

            Properties.WithThreadProperty(Properties.X509Sgp22NameConstraints, bool.TrueString, () =>
            {
                // failure 1: subject carries extra attributes around the constrained O / serialNumber
                Assert.True(IsPermitted(subtreeExtra, subjectExtra),
                    "SGP.22 extra-attributes should be permitted when enabled");

                // failure 2: serialNumber is the leading RDN and must match via startsWith
                Assert.True(IsPermitted(subtreeSnFirst, subjectSnFirst),
                    "SGP.22 leading serialNumber should be permitted when enabled");

                // negative: a required organization that does not match is still rejected
                Assert.False(
                    IsPermitted(subtreeExtra, DirectoryName("O=OTHER, serialNumber=89034011026140000000000000001332")),
                    "mismatched organization must still be rejected");

                // negative: a serialNumber that is not a prefix is still rejected
                Assert.False(
                    IsPermitted(subtreeExtra, DirectoryName("O=VALID, serialNumber=12340000000000000000000000000000")),
                    "non-prefix serialNumber must still be rejected");

                // negative: a required attribute missing entirely is rejected
                Assert.False(IsPermitted(subtreeExtra, DirectoryName("C=ES, O=VALID, CN=VALID EUICC CD")),
                    "missing required serialNumber must be rejected");
            });
        }

        /// <summary>Regression test pinning the lone-serialNumber matching of a directoryName subtree.</summary>
        /// <remarks>
        /// Before github #2327 (bc-java) this GSMA SGP.22 StartsWith concession ran ungated in the strict path; it is
        /// now gated behind <see cref="Properties.X509Sgp22NameConstraints"/>, so default validation applies the
        /// RFC 5280 sec. 7.1 equality comparison and the StartsWith behaviour returns only with the flag.
        /// </remarks>
        [Test]
        public void Sgp22LegacySerialNumber()
        {
            GeneralName subtree = DirectoryName("serialNumber=89034011");
            GeneralName exact = DirectoryName("serialNumber=89034011");
            GeneralName prefix = DirectoryName("serialNumber=89034011026140000000000000001332");

            // default (flag off): RFC 5280 equality - an exact value matches, a longer value does not
            Assert.True(IsPermitted(subtree, exact), "exact serialNumber must match by default");
            Assert.False(IsPermitted(subtree, prefix), "prefix serialNumber must not match by default");

            Properties.WithThreadProperty(Properties.X509Sgp22NameConstraints, bool.TrueString, () =>
            {
                // flag on: the legacy GSMA SGP.22 startsWith comparison applies again
                Assert.True(IsPermitted(subtree, exact), "exact serialNumber must match when enabled");
                Assert.True(IsPermitted(subtree, prefix), "prefix serialNumber must match when enabled");
            });
        }

        private static GeneralName DirectoryName(string name) =>
            new GeneralName(GeneralName.DirectoryName, new X509Name(name));

        private static bool IsPermitted(GeneralName permitted, GeneralName subject)
        {
            PkixNameConstraintValidator validator = new PkixNameConstraintValidator();
            validator.IntersectPermittedSubtree(new GeneralSubtree(permitted));
            try
            {
                validator.CheckPermittedName(subject);
                return true;
            }
            catch (PkixNameConstraintValidatorException)
            {
                return false;
            }
        }

        private static bool IsExcluded(GeneralName excluded, GeneralName name)
        {
            PkixNameConstraintValidator validator = new PkixNameConstraintValidator();
            validator.AddExcludedSubtree(new GeneralSubtree(excluded));
            try
            {
                validator.CheckExcludedName(name);
                return false;
            }
            catch (PkixNameConstraintValidatorException)
            {
                return true;
            }
        }

        private static bool IsPermittedAfterIntersect(GeneralName first, GeneralName second, GeneralName subject)
        {
            PkixNameConstraintValidator validator = new PkixNameConstraintValidator();
            validator.IntersectPermittedSubtree(new GeneralSubtree(first));
            validator.IntersectPermittedSubtree(new GeneralSubtree(second));
            try
            {
                validator.CheckPermittedName(subject);
                return true;
            }
            catch (PkixNameConstraintValidatorException)
            {
                return false;
            }
        }

        private static bool IsExcludedAfterUnion(GeneralName first, GeneralName second, GeneralName name)
        {
            PkixNameConstraintValidator validator = new PkixNameConstraintValidator();
            validator.AddExcludedSubtree(new GeneralSubtree(first));
            validator.AddExcludedSubtree(new GeneralSubtree(second));
            try
            {
                validator.CheckExcludedName(name);
                return false;
            }
            catch (PkixNameConstraintValidatorException)
            {
                return true;
            }
        }

        private static GeneralName UriName(string uri) =>
            new GeneralName(GeneralName.UniformResourceIdentifier, uri);

        private static GeneralName DnsName(string dns) => new GeneralName(GeneralName.DnsName, dns);

        private static GeneralName EmailName(string email) => new GeneralName(GeneralName.Rfc822Name, email);

        private static GeneralName IPName(byte[] ip) =>
            new GeneralName(GeneralName.IPAddress, new DerOctetString(ip));

        // ::ffff:a.b.c.d - a 16-byte IPv4-mapped IPv6 address (RFC 4291 sec. 2.5.5.2).
        private static byte[] IPv4Mapped(int a, int b, int c, int d) =>
            Bytes(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, a, b, c, d);

        private static byte[] Bytes(params int[] values)
        {
            byte[] result = new byte[values.Length];
            for (int i = 0; i < values.Length; i++)
            {
                result[i] = (byte)values[i];
            }
            return result;
        }

        /// <summary>Tests string-based GeneralNames for inclusion or exclusion.</summary>
        /// <param name="nameType">The <see cref="GeneralName"/> type to test.</param>
        /// <param name="testName">The name to test.</param>
        /// <param name="testNameIsConstraint">The names where <paramref name="testName"/> must be included and excluded.</param>
        /// <param name="testNameIsNotConstraint">The names where <paramref name="testName"/> must NOT be excluded and included.</param>
        /// <param name="testNames1">Operand 1 of test names to use for union and intersection testing.</param>
        /// <param name="testNames2">Operand 2 of test names to use for union and intersection testing.</param>
        /// <param name="testUnion">The union results.</param>
        /// <param name="testIntersection">The intersection results.</param>
        private static void TestConstraints(int nameType, string testName, string[] testNameIsConstraint,
            string[] testNameIsNotConstraint, string[] testNames1, string[] testNames2, string[][] testUnion,
            string[] testIntersection)
        {
            for (int i = 0; i < testNameIsConstraint.Length; i++)
            {
                PkixNameConstraintValidator constraintValidator = new PkixNameConstraintValidator();
                constraintValidator.IntersectPermittedSubtree(new GeneralSubtree(
                    new GeneralName(nameType, testNameIsConstraint[i])));
                constraintValidator.CheckPermittedName(new GeneralName(nameType, testName));
            }
            for (int i = 0; i < testNameIsNotConstraint.Length; i++)
            {
                PkixNameConstraintValidator constraintValidator = new PkixNameConstraintValidator();
                constraintValidator.IntersectPermittedSubtree(new GeneralSubtree(
                    new GeneralName(nameType, testNameIsNotConstraint[i])));
                try
                {
                    constraintValidator.CheckPermittedName(new GeneralName(nameType, testName));
                    constraintValidator.CheckPermittedName(new GeneralName(nameType, testName));
                    Assert.Fail("not permitted name allowed: " + nameType);
                }
                catch (PkixNameConstraintValidatorException)
                {
                    // expected
                }
            }
            for (int i = 0; i < testNameIsConstraint.Length; i++)
            {
                PkixNameConstraintValidator constraintValidator = new PkixNameConstraintValidator();
                constraintValidator.AddExcludedSubtree(new GeneralSubtree(new GeneralName(
                    nameType, testNameIsConstraint[i])));
                try
                {
                    constraintValidator.CheckExcludedName(new GeneralName(nameType, testName));
                    Assert.Fail("excluded name missed: " + nameType);
                }
                catch (PkixNameConstraintValidatorException)
                {
                    // expected
                }
            }
            for (int i = 0; i < testNameIsNotConstraint.Length; i++)
            {
                PkixNameConstraintValidator constraintValidator = new PkixNameConstraintValidator();
                constraintValidator.AddExcludedSubtree(new GeneralSubtree(new GeneralName(
                    nameType, testNameIsNotConstraint[i])));
                constraintValidator.CheckExcludedName(new GeneralName(nameType, testName));
            }
            for (int i = 0; i < testNames1.Length; i++)
            {
                PkixNameConstraintValidator constraintValidator = new PkixNameConstraintValidator();
                constraintValidator.AddExcludedSubtree(new GeneralSubtree(new GeneralName(
                    nameType, testNames1[i])));
                constraintValidator.AddExcludedSubtree(new GeneralSubtree(new GeneralName(
                    nameType, testNames2[i])));
                PkixNameConstraintValidator constraints2 = new PkixNameConstraintValidator();
                for (int j = 0; j < testUnion[i].Length; j++)
                {
                    constraints2.AddExcludedSubtree(new GeneralSubtree(
                        new GeneralName(nameType, testUnion[i][j])));
                }
                Assert.AreEqual(constraintValidator, constraints2, $"union wrong: {nameType}");

                constraintValidator = new PkixNameConstraintValidator();
                constraintValidator.IntersectPermittedSubtree(new GeneralSubtree(
                    new GeneralName(nameType, testNames1[i])));
                constraintValidator.IntersectPermittedSubtree(new GeneralSubtree(
                    new GeneralName(nameType, testNames2[i])));
                constraints2 = new PkixNameConstraintValidator();
                if (testIntersection[i] != null)
                {
                    constraints2.IntersectPermittedSubtree(new GeneralSubtree(
                        new GeneralName(nameType, testIntersection[i])));
                }
                else
                {
                    constraints2.IntersectEmptyPermittedSubtree(nameType);
                }
                Assert.AreEqual(constraintValidator, constraints2, $"intersection wrong: {nameType}");
            }
        }

        /// <summary>Tests byte array based GeneralNames for inclusion or exclusion.</summary>
        /// <param name="nameType">The <see cref="GeneralName"/> type to test.</param>
        /// <param name="testName">The name to test.</param>
        /// <param name="testNameIsConstraint">The names where <paramref name="testName"/> must be included and excluded.</param>
        /// <param name="testNameIsNotConstraint">The names where <paramref name="testName"/> must NOT be excluded and included.</param>
        /// <param name="testNames1">Operand 1 of test names to use for union and intersection testing.</param>
        /// <param name="testNames2">Operand 2 of test names to use for union and intersection testing.</param>
        /// <param name="testUnion">The union results.</param>
        /// <param name="testIntersection">The intersection results.</param>
        private static void TestConstraints(int nameType, byte[] testName, byte[][] testNameIsConstraint,
            byte[][] testNameIsNotConstraint, byte[][] testNames1, byte[][] testNames2, byte[][][] testUnion,
            byte[][] testInterSection)
        {
            for (int i = 0; i < testNameIsConstraint.Length; i++)
            {
                PkixNameConstraintValidator constraintValidator = new PkixNameConstraintValidator();
                constraintValidator.IntersectPermittedSubtree(new GeneralSubtree(
                    new GeneralName(nameType, new DerOctetString(testNameIsConstraint[i]))));
                constraintValidator.CheckPermittedName(new GeneralName(nameType,
                    new DerOctetString(testName)));
            }
            for (int i = 0; i < testNameIsNotConstraint.Length; i++)
            {
                PkixNameConstraintValidator constraintValidator = new PkixNameConstraintValidator();
                constraintValidator.IntersectPermittedSubtree(new GeneralSubtree(
                    new GeneralName(nameType, new DerOctetString(testNameIsNotConstraint[i]))));
                try
                {
                    constraintValidator.CheckPermittedName(new GeneralName(nameType,
                        new DerOctetString(testName)));
                    Assert.Fail("not permitted name allowed: " + nameType);
                }
                catch (PkixNameConstraintValidatorException)
                {
                    // expected
                }
            }
            for (int i = 0; i < testNameIsConstraint.Length; i++)
            {
                PkixNameConstraintValidator constraintValidator = new PkixNameConstraintValidator();
                constraintValidator.AddExcludedSubtree(new GeneralSubtree(new GeneralName(
                    nameType, new DerOctetString(testNameIsConstraint[i]))));
                try
                {
                    constraintValidator.CheckExcludedName(new GeneralName(nameType,
                        new DerOctetString(testName)));
                    Assert.Fail("excluded name missed: " + nameType);
                }
                catch (PkixNameConstraintValidatorException)
                {
                    // expected
                }
            }
            for (int i = 0; i < testNameIsNotConstraint.Length; i++)
            {
                PkixNameConstraintValidator constraintValidator = new PkixNameConstraintValidator();
                constraintValidator.AddExcludedSubtree(new GeneralSubtree(new GeneralName(
                    nameType, new DerOctetString(testNameIsNotConstraint[i]))));
                constraintValidator.CheckExcludedName(new GeneralName(nameType,
                    new DerOctetString(testName)));
            }
            for (int i = 0; i < testNames1.Length; i++)
            {
                PkixNameConstraintValidator constraintValidator = new PkixNameConstraintValidator();
                constraintValidator.AddExcludedSubtree(new GeneralSubtree(new GeneralName(
                    nameType, new DerOctetString(testNames1[i]))));
                constraintValidator.AddExcludedSubtree(new GeneralSubtree(new GeneralName(
                    nameType, new DerOctetString(testNames2[i]))));
                PkixNameConstraintValidator constraints2 = new PkixNameConstraintValidator();
                for (int j = 0; j < testUnion[i].Length; j++)
                {
                    constraints2.AddExcludedSubtree(new GeneralSubtree(
                        new GeneralName(nameType, new DerOctetString(
                        testUnion[i][j]))));
                }
                Assert.AreEqual(constraintValidator, constraints2, $"union wrong: {nameType}");

                constraintValidator = new PkixNameConstraintValidator();
                constraintValidator.IntersectPermittedSubtree(new GeneralSubtree(
                    new GeneralName(nameType, new DerOctetString(testNames1[i]))));
                constraintValidator.IntersectPermittedSubtree(new GeneralSubtree(
                    new GeneralName(nameType, new DerOctetString(testNames2[i]))));
                constraints2 = new PkixNameConstraintValidator();
                if (testInterSection[i] != null)
                {
                    constraints2.IntersectPermittedSubtree(new GeneralSubtree(
                        new GeneralName(nameType, new DerOctetString(testInterSection[i]))));
                }
                else
                {
                    constraints2.IntersectEmptyPermittedSubtree(nameType);
                }
                Assert.AreEqual(constraintValidator, constraints2, $"intersection wrong: {nameType}");
            }
        }
    }
}
