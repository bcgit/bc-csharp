using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Asn1.Tests
{
    [TestFixture]
    public class AuthorityKeyIdentifierTest
    {
        [Test]
        public void ValidCombinationsParse()
        {
            // empty SEQUENCE - all fields absent
            AuthorityKeyIdentifier.GetInstance(DerSequence.Empty);

            // keyIdentifier only
            AuthorityKeyIdentifier.GetInstance(
                new DerSequence(new DerTaggedObject(false, 0, new DerOctetString(new byte[20]))));

            GeneralNames issuer = new GeneralNames(new GeneralName(new X509Name("CN=Test")));

            AuthorityKeyIdentifier.GetInstance(new DerSequence(
                new DerTaggedObject(false, 1, issuer),
                new DerTaggedObject(false, 2, DerInteger.One)));

            // all three fields present
            AuthorityKeyIdentifier.GetInstance(new DerSequence(
                new DerTaggedObject(false, 0, new DerOctetString(new byte[20])),
                new DerTaggedObject(false, 1, issuer),
                new DerTaggedObject(false, 2, DerInteger.One)));
        }

        [Test]
        public void InvalidCombinationsRejected()
        {
            // RFC 5280 sec. 4.2.1.1 violation: authorityCertSerialNumber without
            // authorityCertIssuer (issue #2036).
            try
            {
                AuthorityKeyIdentifier.GetInstance(new DerSequence(
                    new DerTaggedObject(false, 2, DerInteger.One)));

                Assert.Fail("authorityCertSerialNumber-only AKI accepted");
            }
            catch (ArgumentException e)
            {
                Assert.True(e.Message.IndexOf("MUST both be present or both be absent") >= 0,
                    "unexpected message: " + e.Message);
            }

            // authorityCertIssuer without authorityCertSerialNumber
            GeneralNames issuer = new GeneralNames(new GeneralName(new X509Name("CN=Test")));
            try
            {
                AuthorityKeyIdentifier.GetInstance(new DerSequence(
                    new DerTaggedObject(false, 1, issuer)));

                Assert.Fail("authorityCertIssuer-only AKI accepted");
            }
            catch (ArgumentException e)
            {
                Assert.True(e.Message.IndexOf("MUST both be present or both be absent") >= 0,
                    "unexpected message: " + e.Message);
            }

            // keyIdentifier present but only one of the issuer/serial pair
            try
            {
                AuthorityKeyIdentifier.GetInstance(new DerSequence(
                    new DerTaggedObject(false, 0, new DerOctetString(new byte[20])),
                    new DerTaggedObject(false, 2, DerInteger.One)));

                Assert.Fail("keyId + serial-only AKI accepted");
            }
            catch (ArgumentException)
            {
                // expected
            }
        }

        [Test]
        public void PublicConstructorsRejectMismatchedIssuerAndSerial()
        {
            GeneralNames issuer = new GeneralNames(new GeneralName(new X509Name("CN=Test")));
            byte[] keyId = new byte[20];

            try
            {
                new AuthorityKeyIdentifier(keyId, issuer, null);
                Assert.Fail("(byte[], GeneralNames, null) accepted");
            }
            catch (ArgumentException)
            {
                // expected
            }

            try
            {
                new AuthorityKeyIdentifier(keyId, null, BigInteger.One);
                Assert.Fail("(byte[], null, BigInteger) accepted");
            }
            catch (ArgumentException)
            {
                // expected
            }

            try
            {
                new AuthorityKeyIdentifier(issuer, null);
                Assert.Fail("(GeneralNames, null) accepted");
            }
            catch (ArgumentException)
            {
                // expected
            }

            try
            {
                new AuthorityKeyIdentifier((GeneralNames)null, BigInteger.One);
                Assert.Fail("(null, BigInteger) accepted");
            }
            catch (ArgumentException)
            {
                // expected
            }

            // matched pairs and absent-pair forms still construct successfully
            new AuthorityKeyIdentifier(keyId);
            new AuthorityKeyIdentifier(keyId, null, null);
            new AuthorityKeyIdentifier(keyId, issuer, BigInteger.One);
            new AuthorityKeyIdentifier(issuer, BigInteger.One);
        }
    }
}
