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

        private readonly byte[] testIP = { 192, 168, 1, 2 };

        // Contiguous CIDR constraints (address || mask). Non-contiguous masks are rejected by default since the
        // CIDR-enforcement change, so these vectors and the intersect/union expectations below are all CIDR.
        private readonly byte[][] testIPIsConstraint = new byte[2][] {
            new byte[] { 192, 168, 1, 0, 0xFF, 0xFF, 0xFF, 0x00 },     // 192.168.1.0/24
            new byte[] { 192, 168, 0, 0, 0xFF, 0xFF, 0x00, 0x00 } };   // 192.168.0.0/16

        private readonly byte[][] testIPIsNotConstraint = new byte[2][] {
            new byte[] { 192, 168, 3, 0, 0xFF, 0xFF, 0xFF, 0x00 },     // 192.168.3.0/24
            new byte[] { 192, 168, 1, 128, 0xFF, 0xFF, 0xFF, 0x80 } }; // 192.168.1.128/25 (excludes .2)

        // i=0 nested (/24 within /16), i=1 identical, i=2 disjoint.
        private readonly byte[][] ip1 = new byte[3][] {
            new byte[] { 192, 168, 0, 0, 0xFF, 0xFF, 0x00, 0x00 },   // 192.168.0.0/16
            new byte[] { 192, 168, 1, 0, 0xFF, 0xFF, 0xFF, 0x00 },   // 192.168.1.0/24
            new byte[] { 192, 168, 0, 0, 0xFF, 0xFF, 0xFF, 0x00 } }; // 192.168.0.0/24

        private readonly byte[][] ip2 = new byte[3][] {
            new byte[] { 192, 168, 1, 0, 0xFF, 0xFF, 0xFF, 0x00 },   // 192.168.1.0/24
            new byte[] { 192, 168, 1, 0, 0xFF, 0xFF, 0xFF, 0x00 },   // 192.168.1.0/24
            new byte[] { 10, 0, 0, 0, 0xFF, 0x00, 0x00, 0x00 } };    // 10.0.0.0/8

        // Intersections: nested -> narrower; identical -> same; disjoint -> empty (null).
        private readonly byte[][] ipintersect = new byte[3][] {
            new byte[] { 192, 168, 1, 0, 0xFF, 0xFF, 0xFF, 0x00 },   // 192.168.1.0/24
            new byte[] { 192, 168, 1, 0, 0xFF, 0xFF, 0xFF, 0x00 }, null };

        // Unions drop a range subsumed by another (CIDR): nested -> broader only, identical -> one, disjoint -> both.
        private readonly byte[][][] ipunion = new byte[3][][] {
            new byte[1][] {
                new byte[] { 192, 168, 0, 0, 0xFF, 0xFF, 0x00, 0x00 } },   // 192.168.0.0/16 (subsumes the /24)
            new byte[1][] {
                new byte[] { 192, 168, 1, 0, 0xFF, 0xFF, 0xFF, 0x00 } },   // 192.168.1.0/24
            new byte[2][] {
                new byte[] { 192, 168, 0, 0, 0xFF, 0xFF, 0xFF, 0x00 },     // 192.168.0.0/24
                new byte[] { 10, 0, 0, 0, 0xFF, 0x00, 0x00, 0x00 } } };    // 10.0.0.0/8

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

            // dNSName: exact and subdomain forms, including the dot-prefixed (proper-subtree) constraint.
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
        /// RFC 1034 sec. 3.5 name syntax has no empty labels: "a..b", repeated trailing dots, or a dot
        /// right after the constraint-form leading dot misalign the per-label compare - on the excluded
        /// side historically a fail-open escape. Such values are rejected at construction (fail-closed),
        /// as constraints and as tested names alike.
        /// </summary>
        [Test]
        public void DnsEmptyLabelRejected()
        {
            string[] malformed = { "a..example.com", "a.example.com..", "..example.com" };

            foreach (string bad in malformed)
            {
                Assert.Throws<PkixNameConstraintValidatorException>(
                    () => new PkixNameConstraintValidator().IntersectPermittedSubtree(
                        new GeneralSubtree(DnsName(bad))),
                    "permitted dNSName constraint must be rejected: " + bad);

                Assert.Throws<PkixNameConstraintValidatorException>(
                    () => new PkixNameConstraintValidator().AddExcludedSubtree(new GeneralSubtree(DnsName(bad))),
                    "excluded dNSName constraint must be rejected: " + bad);
            }

            // A malformed tested name fails closed whenever dNSName constraints are in play: under the old
            // per-label compare an empty label escaped an excluded subtree (fail-open).
            Assert.True(IsExcluded(DnsName("example.com"), DnsName("foo..example.com")),
                "an empty label in a tested name must not escape the excluded subtree");
            Assert.False(IsPermitted(DnsName("example.com"), DnsName("foo..example.com")),
                "an empty label in a tested name must not be permitted");
        }

        /// <summary>
        /// A leading dot on a dNSName constraint is the de facto proper-subtree form (OpenSSL nc_dns, Go
        /// matchDomainConstraint, bc-java): subdomains match, the apex itself does not - unlike the plain
        /// RFC 5280 sec. 4.2.1.10 form, which includes the apex. The form is constraint-only: a leading
        /// dot on a TESTED dNSName is an empty first label and fails closed.
        /// </summary>
        [Test]
        public void DnsLeadingDotConstraintExcludesApex()
        {
            // Proper-subtree semantics, both directions.
            Assert.True(IsExcluded(DnsName(".example.com"), DnsName("foo.example.com")),
                "a subdomain must match the dot-prefixed constraint");
            Assert.False(IsExcluded(DnsName(".example.com"), DnsName("example.com")),
                "the apex must not match the dot-prefixed (proper-subtree) constraint");
            Assert.True(IsPermitted(DnsName(".example.com"), DnsName("a.b.example.com")),
                "a nested subdomain must be permitted by the dot-prefixed constraint");
            Assert.False(IsPermitted(DnsName(".example.com"), DnsName("example.com")),
                "the apex must not be permitted by the dot-prefixed (proper-subtree) constraint");

            // Set algebra across the two spellings: the plain form is the strictly broader set.
            Assert.True(
                IsExcludedAfterUnion(DnsName(".example.com"), DnsName("example.com"), DnsName("example.com")),
                "union with the plain form must keep the apex excluded");
            Assert.False(
                IsPermittedAfterIntersect(DnsName(".example.com"), DnsName("example.com"),
                    DnsName("example.com")),
                "intersection must keep the narrower proper-subtree form: the apex is not permitted");
            Assert.True(
                IsPermittedAfterIntersect(DnsName(".example.com"), DnsName("example.com"),
                    DnsName("foo.example.com")),
                "intersection must still permit subdomains");

            // Constraint-only: a tested dNSName with a leading dot fails closed.
            Assert.True(IsExcluded(DnsName("other.test"), DnsName(".example.com")),
                "a tested dNSName with a leading dot must fail closed");
        }

        /// <summary>
        /// When an equal pair (same names, spelled with differing case) meets in the subtree set algebra,
        /// the FIRST-registered constraint instance survives, uniformly across the name families and both
        /// the intersect and union directions. Purely presentational - equality, hashing and matching are
        /// case-insensitive - but pinned so the convention stays deterministic.
        /// </summary>
        [Test]
        public void EqualConstraintKeepsFirstRegisteredSpelling()
        {
            PkixNameConstraintValidator validator = new PkixNameConstraintValidator();
            validator.IntersectPermittedSubtree(new GeneralSubtree(EmailName("EXAMPLE.com")));
            validator.IntersectPermittedSubtree(new GeneralSubtree(EmailName("example.COM")));
            validator.AddExcludedSubtree(new GeneralSubtree(DnsName("BANK.example")));
            validator.AddExcludedSubtree(new GeneralSubtree(DnsName("bank.EXAMPLE")));
            validator.AddExcludedSubtree(new GeneralSubtree(UriName("HOST.example")));
            validator.AddExcludedSubtree(new GeneralSubtree(UriName("host.EXAMPLE")));

            string rendered = validator.ToString();
            Assert.True(rendered.Contains("EXAMPLE.com") && !rendered.Contains("example.COM"),
                "an equal permitted email pair must keep the first-registered spelling");
            Assert.True(rendered.Contains("BANK.example") && !rendered.Contains("bank.EXAMPLE"),
                "an equal excluded dNSName pair must keep the first-registered spelling");
            Assert.True(rendered.Contains("HOST.example") && !rendered.Contains("host.EXAMPLE"),
                "an equal excluded URI pair must keep the first-registered spelling");
        }

        /// <summary>
        /// An empty directoryName base would be an initial prefix of every DN. It is deliberately inert
        /// instead: it matches no name, and in the subtree set algebra it relates to nothing - so an empty
        /// excluded base must not absorb a real excluded subtree (that would fail open), and an empty
        /// permitted base must not stand in for a real permitted subtree.
        /// </summary>
        [Test]
        public void DirectoryNameEmptyBaseInert()
        {
            GeneralName emptyDn = new GeneralName(GeneralName.DirectoryName,
                X509Name.GetInstance(new DerSequence()));

            // Matching: an empty excluded base catches nothing.
            Assert.False(IsExcluded(emptyDn, DirectoryName("O=Org")),
                "an empty excluded base must match no name");

            // Excluded union, both registration orders: the empty base must not absorb the real subtree.
            Assert.True(IsExcludedAfterUnion(emptyDn, DirectoryName("O=Org"), DirectoryName("O=Org, CN=x")),
                "an empty excluded base must not absorb a later real subtree");
            Assert.True(IsExcludedAfterUnion(DirectoryName("O=Org"), emptyDn, DirectoryName("O=Org, CN=x")),
                "an empty excluded base must not absorb an earlier real subtree");

            // Permitted intersect: empty and real subtrees do not overlap, so the intersection is empty.
            Assert.False(IsPermittedAfterIntersect(emptyDn, DirectoryName("O=Org"), DirectoryName("O=Org, CN=x")),
                "an empty permitted base must not stand in for a real permitted subtree");
        }

        /// <summary>
        /// The union folds decide the incoming constraint's fate against the WHOLE excluded set: a
        /// constraint already subsumed by one existing subtree must not be added just because it is
        /// disjoint from another. (Historically it was - a redundant, subsumed element that broke the
        /// stored sets' pairwise-non-nested minimality and hence validator equality; matching was
        /// unaffected.) Pinned per implementation - the shared host-name union, iPAddress and
        /// directoryName - via validator equality against a registration order without the covered entry.
        /// </summary>
        [Test]
        public void UnionDropsCoveredConstraint()
        {
            // dNSName (the shared host-name union): foo.example.com is inside example.com but disjoint
            // from other.test.
            PkixNameConstraintValidator a = new PkixNameConstraintValidator();
            a.AddExcludedSubtree(new GeneralSubtree(DnsName("example.com")));
            a.AddExcludedSubtree(new GeneralSubtree(DnsName("other.test")));
            a.AddExcludedSubtree(new GeneralSubtree(DnsName("foo.example.com")));

            PkixNameConstraintValidator b = new PkixNameConstraintValidator();
            b.AddExcludedSubtree(new GeneralSubtree(DnsName("example.com")));
            b.AddExcludedSubtree(new GeneralSubtree(DnsName("other.test")));

            Assert.AreEqual(a, b, "a covered dNSName constraint must not enter the union");

            // iPAddress: 10.1.0.0/16 is inside 10.0.0.0/8 but disjoint from 192.168.0.0/16.
            a = new PkixNameConstraintValidator();
            a.AddExcludedSubtree(new GeneralSubtree(IPName(Bytes(10, 0, 0, 0, 255, 0, 0, 0))));
            a.AddExcludedSubtree(new GeneralSubtree(IPName(Bytes(192, 168, 0, 0, 255, 255, 0, 0))));
            a.AddExcludedSubtree(new GeneralSubtree(IPName(Bytes(10, 1, 0, 0, 255, 255, 0, 0))));

            b = new PkixNameConstraintValidator();
            b.AddExcludedSubtree(new GeneralSubtree(IPName(Bytes(10, 0, 0, 0, 255, 0, 0, 0))));
            b.AddExcludedSubtree(new GeneralSubtree(IPName(Bytes(192, 168, 0, 0, 255, 255, 0, 0))));

            Assert.AreEqual(a, b, "a covered iPAddress range must not enter the union");

            // directoryName: O=Org, CN=x is inside O=Org's subtree but disjoint from O=Other.
            a = new PkixNameConstraintValidator();
            a.AddExcludedSubtree(new GeneralSubtree(DirectoryName("O=Org")));
            a.AddExcludedSubtree(new GeneralSubtree(DirectoryName("O=Other")));
            a.AddExcludedSubtree(new GeneralSubtree(DirectoryName("O=Org, CN=x")));

            b = new PkixNameConstraintValidator();
            b.AddExcludedSubtree(new GeneralSubtree(DirectoryName("O=Org")));
            b.AddExcludedSubtree(new GeneralSubtree(DirectoryName("O=Other")));

            Assert.AreEqual(a, b, "a covered directoryName subtree must not enter the union");
        }

        /// <summary>
        /// The rfc822Name/URI HOST part must be free of empty labels, mirroring the dNSName rule
        /// (see <see cref="DnsEmptyLabelOrLeadingDotRejected"/>): ".." (including repeated trailing dots)
        /// misaligns the per-label compare - historically a fail-open escape on the excluded side - and a
        /// leading dot on a host does the same (the ".domain" form is a constraint-only shape, RFC 5280
        /// sec. 4.2.1.10). Rejected at construction (fail-closed) for constraints and tested names alike.
        /// The mailbox LOCAL part stays unrestricted: a quoted local part may legally contain dots.
        /// </summary>
        [Test]
        public void EmailUriEmptyLabelRejected()
        {
            string[] malformed = { "foo..example.com", "..example.com", ".foo..example.com",
                "foo.example.com..", "user@foo..example.com", "user@.example.com" };

            foreach (string bad in malformed)
            {
                foreach (var name in new[] { EmailName(bad), UriName(bad) })
                {
                    Assert.Throws<PkixNameConstraintValidatorException>(
                        () => new PkixNameConstraintValidator().IntersectPermittedSubtree(
                            new GeneralSubtree(name)),
                        "permitted constraint must be rejected: " + name);

                    Assert.Throws<PkixNameConstraintValidatorException>(
                        () => new PkixNameConstraintValidator().AddExcludedSubtree(new GeneralSubtree(name)),
                        "excluded constraint must be rejected: " + name);
                }
            }

            // Tested rfc822Name: the empty label historically escaped the excluded domain subtree.
            Assert.True(IsExcluded(EmailName(".example.com"), EmailName("user@foo..example.com")),
                "an empty label in a tested email host must not escape the excluded subtree");
            Assert.False(IsPermitted(EmailName(".example.com"), EmailName("user@foo..example.com")),
                "an empty label in a tested email host must not be permitted");

            // Tested URI: an extracted host with an empty label or a leading dot fails closed.
            Assert.True(IsExcluded(UriName("example.com"), UriName("https://foo..example.com/")),
                "an empty label in a tested URI host must not escape the excluded subtree");
            Assert.True(IsExcluded(UriName("example.com"), UriName("https://.example.com/")),
                "a leading dot in a tested URI host must fail closed");

            // The mailbox local part is not label-validated (only the host is): a permitted match proves the
            // value was accepted, not rejected.
            Assert.True(IsPermitted(EmailName("example.com"), EmailName("a..b@example.com")),
                "dots in the mailbox local part must not be rejected");
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
            // The path case is the vector reported as ANT-2026-R05HVR25.
            Assert.True(
                IsExcluded(UriName("evil.example"),
                    UriName("http://evil.example/x@allowed.example")),
                "'@' in the path must not be treated as userinfo");
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
        /// Non-contiguous masks are rejected by default, but under the leniency valve a permitted subtree's
        /// mask is rounded up (fill to the last 1-bit) at creation. Two IPv4-mapped ::ffff:192.0.2.0
        /// constraints each with a hole in the /96 prefix therefore round to /120 and collapse to the IPv4
        /// form 192.0.2.0/24; their intersection matches a 4-byte IPv4 SAN in that range. (Formerly
        /// SetAlgebraIpIntersectionMappedResult, whose mask-OR trap relied on the now-disallowed
        /// non-contiguity.)
        /// </summary>
        [Test]
        public void LenientNonContiguousMappedMaskRoundsToCidr()
        {
            // Two 32-byte (IPv6) constraints on ::ffff:192.0.2.0, each with a hole in the /96 prefix
            // (mask byte 11) so the mask is non-contiguous - rejected outright unless leniency is set.
            byte[] mappedHoleFE = Bytes(
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 192, 0, 2, 0,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0x00);
            byte[] mappedHole01 = Bytes(
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 192, 0, 2, 0,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0xFF, 0xFF, 0xFF, 0x00);

            // Default (strict) rejects a non-contiguous mask at registration.
            PkixNameConstraintValidator strict = new PkixNameConstraintValidator();
            Assert.Throws<PkixNameConstraintValidatorException>(
                () => strict.IntersectPermittedSubtree(new GeneralSubtree(IPName(mappedHoleFE))),
                "a non-contiguous mask must be rejected by default");

            Properties.WithThreadProperty(Properties.X509AllowLenientIPAddressMask, bool.TrueString, () =>
            {
                // Each permitted mask rounds up to /120 and collapses to 192.0.2.0/24, so the intersection
                // matches an IPv4 SAN inside the /24 and rejects one outside it.
                Assert.True(
                    IsPermittedAfterIntersect(IPName(mappedHoleFE), IPName(mappedHole01),
                        IPName(Bytes(192, 0, 2, 5))),
                    "salvaged mapped /120 masks must intersect to the IPv4 /24 and match an in-range SAN");
                Assert.False(
                    IsPermittedAfterIntersect(IPName(mappedHoleFE), IPName(mappedHole01),
                        IPName(Bytes(198, 51, 100, 5))),
                    "an IPv4 SAN outside the intersected range must not match");
            });
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

        /// <summary>
        /// Nested domain constraints in the shared host-name algebra: the intersection is the narrower domain,
        /// the union the broader. Guards the Relate classifier's Subsumes/SubsumedBy split - proper domain
        /// subsumption that the other set-algebra tests did not exercise. Both wrapper types are covered
        /// (rfc822Name and, with its mirrored operand order, uniformResourceIdentifier).
        /// </summary>
        [Test]
        public void SetAlgebraHostNameDomainSubsumption()
        {
            // rfc822Name: .example.com strictly contains .sub.example.com.
            Assert.False(
                IsPermittedAfterIntersect(EmailName(".example.com"), EmailName(".sub.example.com"),
                    EmailName("user@x.example.com")),
                "email: intersection of nested domains keeps the narrower, so a name only in the broader fails");
            Assert.True(
                IsPermittedAfterIntersect(EmailName(".example.com"), EmailName(".sub.example.com"),
                    EmailName("user@y.sub.example.com")),
                "email: a name within the narrower domain survives the intersection");
            Assert.True(
                IsExcludedAfterUnion(EmailName(".sub.example.com"), EmailName(".example.com"),
                    EmailName("user@x.example.com")),
                "email: union of nested domains keeps the broader, so a name in it is excluded");

            // uniformResourceIdentifier shares the algebra (mirrored operand order), exercising the other branch.
            Assert.False(
                IsPermittedAfterIntersect(UriName(".example.com"), UriName(".sub.example.com"),
                    UriName("http://x.example.com/")),
                "uri: intersection of nested domains keeps the narrower");
            Assert.True(
                IsExcludedAfterUnion(UriName(".sub.example.com"), UriName(".example.com"),
                    UriName("http://x.example.com/")),
                "uri: union of nested domains keeps the broader");

            // Disjoint domains: the intersection is empty, so a name in *either* operand is not permitted
            // (checking both operands catches a mutation that wrongly keeps one instead of emptying the set).
            Assert.False(
                IsPermittedAfterIntersect(EmailName(".example.com"), EmailName(".example.org"),
                    EmailName("user@x.example.com")),
                "email: intersection of disjoint domains is empty (name in first operand)");
            Assert.False(
                IsPermittedAfterIntersect(EmailName(".example.com"), EmailName(".example.org"),
                    EmailName("user@x.example.org")),
                "email: intersection of disjoint domains is empty (name in second operand)");
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
        /// A non-contiguous iPAddress subnet mask isn't valid CIDR; by default it is rejected (fail-closed)
        /// at registration in both directions (RFC 4632). Salvage requires the leniency valve.
        /// </summary>
        [Test]
        public void NonContiguousMaskRejectedByDefault()
        {
            byte[] nonContiguous = Bytes(192, 168, 1, 0, 0xFF, 0xFF, 0xFF, 0x05);

            PkixNameConstraintValidator validator = new PkixNameConstraintValidator();
            Assert.Throws<PkixNameConstraintValidatorException>(
                () => validator.IntersectPermittedSubtree(new GeneralSubtree(IPName(nonContiguous))),
                "a non-contiguous permitted mask must be rejected by default");
            Assert.Throws<PkixNameConstraintValidatorException>(
                () => validator.AddExcludedSubtree(new GeneralSubtree(IPName(nonContiguous))),
                "a non-contiguous excluded mask must be rejected by default");
        }

        /// <summary>
        /// Under the leniency valve a non-contiguous mask is salvaged to the most-restrictive contiguous mask
        /// for its context: a permitted range is narrowed (fill up to the last 1-bit; under-permit), an
        /// excluded range is broadened (keep only the leading 1-bits; over-exclude). Both can only tighten.
        /// </summary>
        [Test]
        public void LenientNonContiguousMaskRoundingDirection()
        {
            // 192.168.1.0 with a non-contiguous mask 255.255.255.5 (0x05 = bits 0 and 2 of the last byte).
            byte[] constraint = Bytes(192, 168, 1, 0, 0xFF, 0xFF, 0xFF, 0x05);

            Properties.WithThreadProperty(Properties.X509AllowLenientIPAddressMask, bool.TrueString, () =>
            {
                // Permitted -> fill up to the last 1-bit => /32 (narrower). 192.168.1.2 matches the raw mask
                // (2 & 5 == 0) but not the rounded /32.
                Assert.True(IsPermitted(IPName(constraint), IPName(Bytes(192, 168, 1, 0))),
                    "the network address is still permitted after narrowing to /32");
                Assert.False(IsPermitted(IPName(constraint), IPName(Bytes(192, 168, 1, 2))),
                    "a permitted non-contiguous mask must narrow, rejecting a raw-mask match (under-permit)");

                // Excluded -> keep only the leading 1-bits => /24 (broader). 192.168.1.1 misses the raw mask
                // (1 & 5 == 1) but is excluded by the rounded /24.
                Assert.True(IsExcluded(IPName(constraint), IPName(Bytes(192, 168, 1, 1))),
                    "an excluded non-contiguous mask must broaden, catching a raw-mask miss (over-exclude)");
            });
        }

        /// <summary>
        /// The base's host bits (those cleared by the mask) are zeroed at construction, so constraints for the
        /// same network compare equal / dedupe regardless of the base's host bits. Matching is unaffected.
        /// </summary>
        [Test]
        public void IpConstraintHostBitsZeroed()
        {
            byte[] dirty = Bytes(192, 168, 1, 7, 0xFF, 0xFF, 0xFF, 0x00);   // 192.168.1.7/24 (dirty host bits)
            byte[] clean = Bytes(192, 168, 1, 0, 0xFF, 0xFF, 0xFF, 0x00);   // 192.168.1.0/24

            PkixNameConstraintValidator a = new PkixNameConstraintValidator();
            a.AddExcludedSubtree(new GeneralSubtree(IPName(dirty)));
            PkixNameConstraintValidator b = new PkixNameConstraintValidator();
            b.AddExcludedSubtree(new GeneralSubtree(IPName(clean)));

            Assert.AreEqual(a, b, "same-network constraints must be equal regardless of base host bits");
            Assert.AreEqual(a.GetHashCode(), b.GetHashCode(), "hash codes must agree for equal validators");

            // Matching is unaffected: the dirty-base constraint still matches every address in the /24.
            Assert.True(IsExcluded(IPName(dirty), IPName(Bytes(192, 168, 1, 200))),
                "host bits in the base must not change which addresses match");
        }

        /// <summary>
        /// With ranges canonicalised to CIDR, the excluded union drops a range subsumed by another (keeping
        /// the broader) in either insertion order, instead of the former keep-both over-approximation;
        /// disjoint ranges are both retained. Matching is unchanged either way.
        /// </summary>
        [Test]
        public void IpUnionDropsSubsumedRange()
        {
            byte[] broad = Bytes(192, 168, 0, 0, 0xFF, 0xFF, 0x00, 0x00);   // 192.168.0.0/16
            byte[] narrow = Bytes(192, 168, 1, 0, 0xFF, 0xFF, 0xFF, 0x00);  // 192.168.1.0/24 (within /16)
            byte[] other = Bytes(10, 0, 0, 0, 0xFF, 0x00, 0x00, 0x00);      // 10.0.0.0/8 (disjoint)

            PkixNameConstraintValidator justBroad = new PkixNameConstraintValidator();
            justBroad.AddExcludedSubtree(new GeneralSubtree(IPName(broad)));

            // narrow then broad: the broader subsumes the already-present narrow.
            PkixNameConstraintValidator narrowFirst = new PkixNameConstraintValidator();
            narrowFirst.AddExcludedSubtree(new GeneralSubtree(IPName(narrow)));
            narrowFirst.AddExcludedSubtree(new GeneralSubtree(IPName(broad)));
            Assert.AreEqual(justBroad, narrowFirst, "broad must subsume an already-present narrow range");

            // broad then narrow: the new narrow is subsumed by the present broad.
            PkixNameConstraintValidator broadFirst = new PkixNameConstraintValidator();
            broadFirst.AddExcludedSubtree(new GeneralSubtree(IPName(broad)));
            broadFirst.AddExcludedSubtree(new GeneralSubtree(IPName(narrow)));
            Assert.AreEqual(justBroad, broadFirst, "a new narrow range subsumed by a present broad is dropped");

            // Disjoint ranges are both kept.
            PkixNameConstraintValidator disjoint = new PkixNameConstraintValidator();
            disjoint.AddExcludedSubtree(new GeneralSubtree(IPName(broad)));
            disjoint.AddExcludedSubtree(new GeneralSubtree(IPName(other)));
            Assert.AreNotEqual(justBroad, disjoint, "a disjoint excluded range must be kept, not dropped");
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

        /// <summary>
        /// A tested rfc822Name with more than one '@' is ambiguous - a quoted local part may legally
        /// contain '@' (RFC 5321 sec. 4.1.2), so the domain is after the LAST '@', not the first. Rather than
        /// split at the first '@' into a wrong host that could evade a constraint, such a name is rejected
        /// fail-closed when email constraints are present; with none, it is tolerated (strict-when-constrained).
        /// The <see cref="Properties.X509AllowLenientRfc822Name"/> safety valve restores the legacy parsing.
        /// </summary>
        [Test]
        public void QuotedLocalPartEmailRejected()
        {
            // A genuine evil.com mailbox with a quoted local part; a first-'@' split yields host
            // b"@evil.com, which would slip past the excluded evil.com subtree.
            Assert.True(IsExcluded(EmailName("evil.com"), EmailName("\"a@b\"@evil.com")),
                "an ambiguous multi-'@' rfc822Name must be caught (fail-closed) by an excluded constraint");

            // The exact PoC vector from the feedback-crypto report: effective domain (after the last '@')
            // is excluded.example.com, but a first-'@' split compared evil.com"@excluded.example.com and
            // missed the excluded subtree.
            Assert.True(
                IsExcluded(EmailName("excluded.example.com"),
                    EmailName("\"user@evil.com\"@excluded.example.com")),
                "the reported quoted-local-part vector must be caught by the excluded subtree");

            // Any multi-'@' tested name fails closed under a permitted constraint too.
            Assert.False(IsPermitted(EmailName("bank.com"), EmailName("\"a@b\"@bank.com")),
                "an ambiguous multi-'@' rfc822Name must not satisfy a permitted constraint");

            // Strict-when-constrained: with no email constraints in play, the ambiguous name is tolerated.
            PkixNameConstraintValidator validator = new PkixNameConstraintValidator();
            validator.CheckPermittedName(EmailName("\"a@b\"@evil.com"));
            validator.CheckExcludedName(EmailName("\"a@b\"@evil.com"));

            // A normal single-'@' address is unaffected.
            Assert.False(IsExcluded(EmailName("evil.com"), EmailName("user@safe.com")),
                "a normal single-'@' address must not be affected");

            // The safety valve restores the legacy lenient parsing: the ambiguous name is no longer
            // rejected (it falls back to the first-'@' split and simply fails to match, as before the fix).
            Properties.WithThreadProperty(Properties.X509AllowLenientRfc822Name, bool.TrueString, () =>
            {
                Assert.False(IsExcluded(EmailName("evil.com"), EmailName("\"a@b\"@evil.com")),
                    "the lenient valve must disable the ambiguity rejection");
            });
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

        /// <summary>
        /// SGP.22 mandates the eUICC serialNumber (the EID) as a decimal PrintableString, so the IIN
        /// prefix rule holds the SUBJECT side to that encoding; a subject serialNumber in any other
        /// encoding falls back to ordinary (canonical, whole-value) RDN equality instead of throwing from
        /// an ASN.1 accessor mid-check. The CONSTRAINT side is trust-side data and is read as any ASN.1
        /// string form: X.520's PrintableString syntax binds it only by inheritance, and rejecting a
        /// misencoded IIN would reject every leaf under that EUM.
        /// </summary>
        [Test]
        public void Sgp22NonPrintableSerialNumber()
        {
            GeneralName subtree = DirectoryName("O=VALID, serialNumber=89034011");

            // O=VALID with the full EID as a (nonconforming) UTF8String serialNumber.
            GeneralName subjectUtf8Sn = new GeneralName(GeneralName.DirectoryName, new DerSequence(
                new DerSet(new DerSequence(X509Name.O, new DerPrintableString("VALID"))),
                new DerSet(new DerSequence(X509Name.SerialNumber,
                    new DerUtf8String("89034011026140000000000000001332")))));

            GeneralName subtreeUtf8Sn = new GeneralName(GeneralName.DirectoryName, new DerSequence(
                new DerSet(new DerSequence(X509Name.O, new DerPrintableString("VALID"))),
                new DerSet(new DerSequence(X509Name.SerialNumber,
                    new DerUtf8String("89034011026140000000000000001332")))));

            // The IIN as a (misencoded) UTF8String in the constraint itself.
            GeneralName subtreeUtf8Iin = new GeneralName(GeneralName.DirectoryName, new DerSequence(
                new DerSet(new DerSequence(X509Name.O, new DerPrintableString("VALID"))),
                new DerSet(new DerSequence(X509Name.SerialNumber, new DerUtf8String("89034011")))));

            Properties.WithThreadProperty(Properties.X509Sgp22NameConstraints, bool.TrueString, () =>
            {
                Assert.False(IsPermitted(subtree, subjectUtf8Sn),
                    "a non-PrintableString EID must not prefix-match the IIN (and must not throw)");
                Assert.True(IsPermitted(subtreeUtf8Sn, subjectUtf8Sn),
                    "identical nonconforming serialNumbers must still match by ordinary equality");
                Assert.True(
                    IsPermitted(subtreeUtf8Iin,
                        DirectoryName("O=VALID, serialNumber=89034011026140000000000000001332")),
                    "a misencoded constraint IIN must still prefix-match a conforming EID");
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
