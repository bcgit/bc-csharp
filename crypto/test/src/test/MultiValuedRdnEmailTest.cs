using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X500;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Tests
{
    /// <summary>Covers the multi-valued RDN <c>EmailAddress</c> handling.</summary>
    /// <remarks>
    /// A subject DN can carry an <c>EmailAddress</c> attribute inside a multi-valued RDN (alongside, say, a <c>CN</c>,
    /// and such an address must be subjected to email name constraints rather than slipping past them.
    /// </remarks>
    [TestFixture]
    public class MultiValuedRdnEmailTest
    {
        private static readonly X509DefaultEntryConverter Converter = new X509DefaultEntryConverter();

        // Tests assembly-internal functionality; the code is kept for re-enabling if InternalsVisibleTo is ever added, or for
        // periodic explicit testing.
#if false
        [Test]
        public void ExtractEmailAddressesFromSubjectDN()
        {
            // a plain, single-valued emailAddress RDN
            {
                var single = X509Name.GetInstance(DerSequence.FromElements(
                    new Rdn[]
                    {
                        BuildRdn(X509Name.O, "Test Org"),
                        BuildRdn(X509Name.EmailAddress, "single@example.com"),
                    }));

                AssertEmails("single-valued", new string[]{ "single@example.com" }, single);
            }

            // an emailAddress packed into a multi-valued RDN alongside a CN - the case the fix targets
            {
                var multi = X509Name.GetInstance(DerSequence.FromElements(
                    new Rdn[]
                    {
                        BuildRdn(X509Name.O, "Test Org"),
                        new Rdn(new AttributeTypeAndValue[]
                        {
                            BuildAttributeTypeAndValue(X509Name.CN, "John Doe"),
                            BuildAttributeTypeAndValue(X509Name.EmailAddress, "multi@example.com"),
                        }),
                    }));

                AssertEmails("multi-valued", new string[]{ "multi@example.com" }, multi);
            }

            // more than one emailAddress, returned in DN order
            {
                var two = X509Name.GetInstance(DerSequence.FromElements(
                    new Rdn[]
                    {
                        BuildRdn(X509Name.EmailAddress, "first@example.com"),
                        new Rdn(new AttributeTypeAndValue[]
                        {
                            BuildAttributeTypeAndValue(X509Name.CN, "John Doe"),
                            BuildAttributeTypeAndValue(X509Name.EmailAddress, "second@example.com"),
                        }),
                    }));

                AssertEmails("two emails", new string[]{ "first@example.com", "second@example.com" }, two);
            }

            // no emailAddress at all
            {
                var none = X509Name.GetInstance(DerSequence.FromElements(
                    new Rdn[]
                    {
                        BuildRdn(X509Name.O, "Test Org"),
                        BuildRdn(X509Name.CN, "John Doe"),
                    }));

                AssertEmails("no email", new string[0], none);
            }

            // a null DN must not blow up
            AssertEmails("null DN", new string[0], null);
        }

        private void AssertEmails(string label, string[] expected, X509Name dn)
        {
            var actual = Rfc3280CertPathUtilities.ExtractEmailAddressesFromSubjectDN(dn).ToArray();
            Assert.That(Utilities.Arrays.AreEqual(expected, actual),
                label + ": expected " + Utilities.Arrays.ToString(expected) + " but got "
                    + Utilities.Arrays.ToString(actual));
        }
#endif

        /// <summary>End-to-end multi-valued RDN <c>EmailAddress</c> test.</summary>
        /// <remarks>
        /// A name-constrained intermediate excludes the <c>example.com</c> mail host, and an end-entity certificate
        /// carries <c>user@example.com</c> inside a multi-valued RDN of its subject DN. Path validation must reject it
        /// - the email must be caught by the excluded subtree even though it is not a standalone RDN and not in a
        /// SubjectAltName.
        /// </remarks>
        [Test]
        public void MultiValuedRdnEmailExcludedByNameConstraint()
        {
            var rootKP = TestUtilities.GenerateRsaKeyPair();
            var intKP = TestUtilities.GenerateRsaKeyPair();
            var eeKP = TestUtilities.GenerateRsaKeyPair();

            var rootName = new X509Name("CN=BC MultiValuedRDN Root");
            var intName = new X509Name("CN=BC MultiValuedRDN Intermediate");

            // self-signed root (CA), used as the trust anchor
            X509Certificate root = TestUtilities.CreateCert(rootName, rootKP.Private, rootName, "SHA256withRSA",
                CAExtensions(null), rootKP.Public);

            GeneralSubtrees excludedSubtrees = new GeneralSubtrees(
                new GeneralSubtree(new GeneralName(GeneralName.Rfc822Name, "example.com")));

            // intermediate excludes the example.com mail host
            NameConstraints excludeExampleCom = new NameConstraints(permittedSubtrees: null, excludedSubtrees);
            X509Certificate intermediate = TestUtilities.CreateCert(rootName, rootKP.Private, intName, "SHA256withRSA",
                CAExtensions(excludeExampleCom), intKP.Public);

            // end-entity with the email inside a multi-valued RDN of the subject DN
            X509Certificate excludedEE = TestUtilities.CreateCert(intName, intKP.Private,
                MultiValuedSubject("user@example.com"), "SHA256withRSA", EndEntityExtensions(), eeKP.Public);

            Assert.Throws<PkixCertPathValidatorException>(() => Validate(excludedEE, intermediate, root),
                "multi-valued RDN email under an excluded subtree was not rejected");

            // a control: the same shape, but the email is NOT under the excluded host, so it validates
            X509Certificate permittedEE = TestUtilities.CreateCert(intName, intKP.Private,
                MultiValuedSubject("user@other.example.org"), "SHA256withRSA", EndEntityExtensions(), eeKP.Public);

            Validate(permittedEE, intermediate, root);
        }

        private static X509Extensions CAExtensions(NameConstraints nameConstraints)
        {
            X509ExtensionsGenerator extGen = new X509ExtensionsGenerator();
            extGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(cA: true));
            if (nameConstraints != null)
            {
                extGen.AddExtension(X509Extensions.NameConstraints, true, nameConstraints);
            }
            return extGen.Generate();
        }

        private static AttributeTypeAndValue BuildAttributeTypeAndValue(DerObjectIdentifier oid, string value) =>
            new AttributeTypeAndValue(oid, Converter.GetConvertedValue(oid, value));

        private static Rdn BuildRdn(DerObjectIdentifier oid, string value) =>
            new Rdn(BuildAttributeTypeAndValue(oid, value));

        private static X509Extensions EndEntityExtensions()
        {
            X509ExtensionsGenerator extGen = new X509ExtensionsGenerator();
            extGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(cA: false));
            return extGen.Generate();
        }

        private static X509Name MultiValuedSubject(string email)
        {
            return X509Name.GetInstance(DerSequence.FromElements(
                new Rdn[]
                {
                    BuildRdn(X509Name.O, "Test Org"),
                    new Rdn(new AttributeTypeAndValue[]
                    {
                        BuildAttributeTypeAndValue(X509Name.CN, "John Doe"),
                        BuildAttributeTypeAndValue(X509Name.EmailAddress, email),
                    }),
                }));
        }

        private static void Validate(X509Certificate ee, X509Certificate intermediate, X509Certificate root)
        {
            var certs = new List<X509Certificate>();
            certs.Add(ee);
            certs.Add(intermediate);

            var certPath = new PkixCertPath(certs);

            var trustAnchors = new HashSet<TrustAnchor>();
            trustAnchors.Add(new TrustAnchor(root, null));

            var pkixParams = new PkixParameters(trustAnchors);
            pkixParams.IsRevocationEnabled = false;

            PkixCertPathValidator validator = new PkixCertPathValidator();
            //PkixCertPathValidatorResult result =
            validator.Validate(certPath, pkixParams);
        }
    }
}
