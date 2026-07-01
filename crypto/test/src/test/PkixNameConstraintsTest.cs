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
