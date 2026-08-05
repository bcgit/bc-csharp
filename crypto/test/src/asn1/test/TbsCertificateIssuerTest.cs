using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.X500;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Tests
{
    [TestFixture]
    public class TbsCertificateIssuerTest
    {
        [Test]
        public void EmptyIssuerProperty()
        {
            byte[] encoded = CreateEmptyIssuerTbs();

            Properties.WithThreadProperty(Properties.X509AllowEmptyIssuerCert, bool.TrueString, () =>
            {
                // the read-side concession for non-PKIX profiles (github bc-java #2387): the parse
                // accepts the empty issuer and round-trips the original encoding...
                TbsCertificateStructure cert = TbsCertificateStructure.GetInstance(encoded);

                Assert.True(cert.Issuer.IsEmpty, "issuer not empty");
                Assert.That(Arrays.AreEqual(encoded, cert.GetEncoded(Asn1Encodable.Der)), "encoding not preserved");

                // ...and generation stays strict.
                ImplPublicConstructorRejectsEmptyIssuer();
                ImplV1GeneratorRejectsEmptyIssuer();
                ImplV3GeneratorRejectsEmptyIssuer();
            });
        }

        [Test]
        public void ParseRejectsEmptyIssuer()
        {
            byte[] encoded = CreateEmptyIssuerTbs();

            try
            {
                TbsCertificateStructure.GetInstance(encoded);
                Assert.Fail("empty issuer DN accepted on parse");
            }
            catch (ArgumentException e)
            {
                Assert.That(e.Message.IndexOf("empty distinguished name") >= 0, "unexpected message: " + e.Message);
            }
        }

        [Test]
        public void PublicConstructorRejectsEmptyIssuer() => ImplPublicConstructorRejectsEmptyIssuer();

        [Test]
        public void V1GeneratorRejectsEmptyIssuer() => ImplV1GeneratorRejectsEmptyIssuer();

        [Test]
        public void V3GeneratorRejectsEmptyIssuer() => ImplV3GeneratorRejectsEmptyIssuer();

        private static byte[] CreateEmptyIssuerTbs()
        {
            // Build a v1 TBSCertificate with an empty issuer DN.
            Asn1EncodableVector v = new Asn1EncodableVector();
            v.Add(DerInteger.One);
            v.Add(new AlgorithmIdentifier(new DerObjectIdentifier("1.2.840.113549.1.1.11")));
            v.Add(X509Name.GetInstance(DerSequence.Empty));
            v.Add(Validity());
            v.Add(SubjectName());
            v.Add(Spki());
            return new DerSequence(v).GetEncoded(Asn1Encodable.Der);
        }
  
        private static void ImplPublicConstructorRejectsEmptyIssuer()
        {
            try
            {
                new TbsCertificateStructure(
                    DerInteger.Two,
                    DerInteger.One,
                    new AlgorithmIdentifier(new DerObjectIdentifier("1.2.840.113549.1.1.11")),
                    X509Name.GetInstance(DerSequence.Empty),
                    Validity(),
                    SubjectName(),
                    Spki(),
                    null, null, null);
                Assert.Fail("public constructor accepted empty issuer");
            }
            catch (ArgumentException)
            {
                // expected
            }
        }

        private static void ImplV1GeneratorRejectsEmptyIssuer()
        {
            V1TbsCertificateGenerator gen = new V1TbsCertificateGenerator();
            gen.SetSerialNumber(DerInteger.One);
            gen.SetSignature(new AlgorithmIdentifier(new DerObjectIdentifier("1.2.840.113549.1.1.11")));
            gen.SetIssuer(X509Name.GetInstance(DerSequence.Empty));
            gen.SetStartDate(NotBefore());
            gen.SetEndDate(NotAfter());
            gen.SetSubject(SubjectName());
            gen.SetSubjectPublicKeyInfo(Spki());

            try
            {
                gen.GenerateTbsCertificate();
                Assert.Fail("V1 generator accepted empty issuer");
            }
            catch (InvalidOperationException)
            {
                // expected
            }
        }

        private static void ImplV3GeneratorRejectsEmptyIssuer()
        {
            V3TbsCertificateGenerator gen = new V3TbsCertificateGenerator();
            gen.SetSerialNumber(DerInteger.One);
            gen.SetSignature(new AlgorithmIdentifier(new DerObjectIdentifier("1.2.840.113549.1.1.11")));
            gen.SetIssuer(X509Name.GetInstance(DerSequence.Empty));
            gen.SetStartDate(NotBefore());
            gen.SetEndDate(NotAfter());
            gen.SetSubject(SubjectName());
            gen.SetSubjectPublicKeyInfo(Spki());

            try
            {
                gen.GenerateTbsCertificate();
                Assert.Fail("V3 generator accepted empty issuer");
            }
            catch (InvalidOperationException)
            {
                // expected
            }

            try
            {
                gen.GeneratePreTbsCertificate();
                Assert.Fail("V3 generator pre-tbs accepted empty issuer");
            }
            catch (InvalidOperationException)
            {
                // expected
            }
        }

        private static Time NotAfter() => new Time(new DerUtcTime("260101000000Z"));

        private static Time NotBefore() => new Time(new DerUtcTime("250101000000Z"));

        private static SubjectPublicKeyInfo Spki()
        {
            return new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(new DerObjectIdentifier("1.2.840.113549.1.1.1")),
                new DerBitString(new byte[]{ 0 }));
        }

        private static X509Name SubjectName() =>
            X509Name.GetInstance(new DerSequence(new Rdn(X509Name.CN, new DerUtf8String("Subject"))));

        private static Validity Validity() => new Validity(NotBefore(), NotAfter());
    }
}
