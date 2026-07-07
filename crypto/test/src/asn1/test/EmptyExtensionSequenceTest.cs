using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Tests
{
    /// <summary>
    /// Several X.509 extension values are defined as SEQUENCE SIZE (1..MAX) by RFC 5280, so an empty SEQUENCE is
    /// malformed and must be rejected with an <see cref="ArgumentException"/> on the parse path.
    /// </summary>
    [TestFixture]
    public class EmptyExtensionSequenceTest
    {
        [Test]
        public void EmptyAuthorityInformationAccess()
        {
            // AuthorityInfoAccessSyntax ::= Sequence SIZE(1..MAX) OF AccessDescription
            RejectEmpty(nameof(AuthorityInformationAccess), AuthorityInformationAccess.GetInstance);
        }

        [Test]
        public void EmptyCertificatePolicies()
        {
            // CertificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation (RFC 5280 sec. 4.2.1.4)
            RejectEmpty(nameof(CertificatePolicies), CertificatePolicies.GetInstance);
        }

        [Test]
        public void EmptyCrlDistPoint()
        {
            // CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint (RFC 5280 sec. 4.2.1.13)
            RejectEmpty(nameof(CrlDistPoint), CrlDistPoint.GetInstance);
        }

        [Test]
        public void EmptyExtendedKeyUsage()
        {
            // ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId (RFC 5280 sec. 4.2.1.12)
            RejectEmpty(nameof(ExtendedKeyUsage), ExtendedKeyUsage.GetInstance);
        }

        [Test]
        public void EmptyGeneralSubtrees()
        {
            // GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree (RFC 5280 sec. 4.2.1.10)
            RejectEmpty(nameof(GeneralSubtrees), GeneralSubtrees.GetInstance);
        }

        [Test]
        public void EmptyPolicyMappings()
        {
            // PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {...} (RFC 5280 sec. 4.2.1.5)
            RejectEmpty(nameof(PolicyMappings), PolicyMappings.GetInstance);
        }

        [Test]
        public void EmptySubjectDirectoryAttributes()
        {
            // SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF Attribute (RFC 5280 sec. 4.2.1.8)
            RejectEmpty(nameof(SubjectDirectoryAttributes), SubjectDirectoryAttributes.GetInstance);
        }

        private static void RejectEmpty(string name, Func<object, Asn1Encodable> getInstance)
        {
            try
            {
                getInstance.Invoke(DerSequence.Empty);
                Assert.Fail($"empty {name} sequence accepted");
            }
            catch (ArgumentException e)
            {
                Assert.NotNull(e.Message);
                Assert.That(e.Message.StartsWith("Minimum sequence size "));
            }
        }
    }
}
