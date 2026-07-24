using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.X500;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Tests
{
    [TestFixture]
    public class AttributeCertificateInfoIssuerTest
    {
        [Test]
        public void ParseRejectsEmptyV1Issuer()
        {
            // v1 form: AttCertIssuer = empty GeneralNames sequence.
            byte[] encoded = BuildAttrCertInfo(new DerSequence()).GetEncoded(Asn1Encodable.Der);
            try
            {
                AttributeCertificateInfo.GetInstance(encoded);
                Assert.Fail("empty v1 GeneralNames issuer accepted");
            }
            catch (ArgumentException e)
            {
                Assert.That(e.Message.IndexOf("empty") >= 0, "unexpected message: " + e.Message);
            }
        }

        [Test]
        public void ParseRejectsEmptyV2Issuer()
        {
            // v2 form: V2Form with no issuerName/baseCertificateID/objectDigestInfo.
            byte[] encoded = BuildAttrCertInfo(new DerTaggedObject(false, 0, new DerSequence())).GetEncoded(Asn1Encodable.Der);
            try
            {
                AttributeCertificateInfo.GetInstance(encoded);
                Assert.Fail("empty v2 V2Form issuer accepted");
            }
            catch (ArgumentException e)
            {
                Assert.That(e.Message.IndexOf("empty") >= 0, "unexpected message: " + e.Message);
            }
        }

        private void GeneratorRejectsEmptyIssuer()
        {
            V2AttributeCertificateInfoGenerator gen = new V2AttributeCertificateInfoGenerator();
            gen.SetHolder(CreateHolder());
            gen.SetIssuer(new AttCertIssuer(new V2Form(new GeneralNames(new GeneralName[0]))));
            gen.SetSignature(new AlgorithmIdentifier(new DerObjectIdentifier("1.2.840.113549.1.1.11")));
            gen.SetSerialNumber(DerInteger.One);
            gen.SetStartDate(new Asn1GeneralizedTime("20250101000000Z"));
            gen.SetEndDate(new Asn1GeneralizedTime("20260101000000Z"));

            try
            {
                gen.GenerateAttributeCertificateInfo();
                Assert.Fail("V2 attr cert generator accepted empty issuer");
            }
            catch (InvalidOperationException)
            {
                // expected
            }
        }

        private static DerSequence BuildAttrCertInfo(object issuer)
        {
            Asn1EncodableVector v = new Asn1EncodableVector();
            v.Add(DerInteger.One);                      // version v2
            v.Add(CreateHolder().ToAsn1Object());       // holder
            v.Add((Asn1Encodable)issuer);               // issuer (CHOICE)
            v.Add(new AlgorithmIdentifier(new DerObjectIdentifier("1.2.840.113549.1.1.11")));
            v.Add(DerInteger.One);                      // serial
            v.Add(new AttCertValidityPeriod(
                new Asn1GeneralizedTime("20250101000000Z"),
                new Asn1GeneralizedTime("20260101000000Z")));
            v.Add(new DerSequence());                   // attributes (empty seq is OK at parse time)
            return new DerSequence(v);
        }

        private static Holder CreateHolder()
        {
            return new Holder(new GeneralNames(new GeneralName(X509Name.GetInstance(
                new DerSequence(new Rdn(X509Name.CN, new DerUtf8String("Holder")))))));
        }
    }
}
