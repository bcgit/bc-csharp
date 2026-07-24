using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.X500;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Tests
{
    [TestFixture]
    public class TbsCertListTest
    {
        [Test]
        public void EmptyIssuerDNRejected()
        {
            // RFC 5280 sec. 5.1.2.3 requires the CRL issuer field to contain a non-empty distinguished name.
            byte[] encoded = BuildCrlBody(X509Name.GetInstance(DerSequence.Empty)).GetEncoded(Asn1Encodable.Der);
            try
            {
                TbsCertificateList.GetInstance(encoded);
                Assert.Fail("empty issuer DN accepted");
            }
            catch (ArgumentException e)
            {
                Assert.That(e.Message.IndexOf("empty distinguished name") >= 0, "unexpected message: " + e.Message);
            }
        }

        [Test]
        public void NonEmptyIssuerDNAccepted()
        {
            X509Name issuer = X509Name.GetInstance(new DerSequence(new Rdn(X509Name.CN, new DerUtf8String("Test CA"))));
            byte[] encoded = BuildCrlBody(issuer).GetEncoded(Asn1Encodable.Der);

            TbsCertificateList tbs = TbsCertificateList.GetInstance(encoded);

            Assert.That(tbs.Issuer.Equivalent(issuer), "issuer mismatch on roundtrip");
        }

        [Test]
        public void V2GeneratorRejectsEmptyIssuer()
        {
            V2TbsCertListGenerator gen = new V2TbsCertListGenerator();
            gen.SetSignature(new AlgorithmIdentifier(new DerObjectIdentifier("1.2.840.113549.1.1.11")));
            gen.SetIssuer(X509Name.GetInstance(DerSequence.Empty));
            gen.SetThisUpdate(new Time(new DerUtcTime("250101000000Z")));

            try
            {
                gen.GenerateTbsCertList();
                Assert.Fail($"{nameof(V2TbsCertListGenerator)} accepted empty issuer");
            }
            catch (InvalidOperationException)
            {
                // expected
            }

            try
            {
                gen.GeneratePreTbsCertList();
                Assert.Fail($"{nameof(V2TbsCertListGenerator)} pre-tbs accepted empty issuer");
            }
            catch (InvalidOperationException)
            {
                // expected
            }
        }

        private static DerSequence BuildCrlBody(X509Name issuer)
        {
            Asn1EncodableVector v = new Asn1EncodableVector();
            v.Add(DerInteger.One);
            v.Add(new AlgorithmIdentifier(new DerObjectIdentifier("1.2.840.113549.1.1.11")));
            v.Add(issuer);
            v.Add(new DerUtcTime("250101000000Z"));
            return new DerSequence(v);
        }
    }
}
