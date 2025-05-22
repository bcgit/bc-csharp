using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.BC;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Tests
{
	[TestFixture]
    public class LinkedCertificateTest
        : Asn1UnitTest
    {
        public override string Name => "LinkedCertificate";

        public override void PerformTest()
        {
            DigestInfo digInfo = new DigestInfo(new AlgorithmIdentifier(NistObjectIdentifiers.IdSha256), new byte[32]);
            GeneralName certLocation = new GeneralName(GeneralName.UniformResourceIdentifier,
                "https://www.bouncycastle.org/certs");
            X509Name certIssuer = null;
            GeneralNames cACerts = null;

            LinkedCertificate linked = new LinkedCertificate(digInfo, certLocation);

            CheckConstruction(linked, digInfo, certLocation, certIssuer, cACerts);

            certIssuer = new X509Name("CN=Test");
            cACerts = new GeneralNames(new GeneralName(new X509Name("CN=CA Test")));

            linked = new LinkedCertificate(digInfo, certLocation, certIssuer, cACerts);

            CheckConstruction(linked, digInfo, certLocation, certIssuer, cACerts);

            linked = LinkedCertificate.GetInstance(null);

            if (linked != null)
            {
                Fail("null GetInstance() failed.");
            }

            try
            {
                LinkedCertificate.GetInstance(new object());

                Fail("GetInstance() failed to detect bad object.");
            }
            catch (ArgumentException)
            {
                // expected
            }
        }

        private void CheckConstruction(LinkedCertificate linked, DigestInfo digestInfo, GeneralName certLocation,
            X509Name certIssuer, GeneralNames caCerts)
        {
            CheckValues(linked, digestInfo, certLocation, certIssuer, caCerts);

            linked = LinkedCertificate.GetInstance(linked);

            CheckValues(linked, digestInfo, certLocation, certIssuer, caCerts);

            linked = LinkedCertificate.GetInstance(linked.GetEncoded());

            CheckValues(linked, digestInfo, certLocation, certIssuer, caCerts);
        }

        private void CheckValues(LinkedCertificate linked, DigestInfo digestInfo, GeneralName certLocation,
            X509Name certIssuer, GeneralNames caCerts)
        {
            checkMandatoryField("digest", digestInfo, linked.Digest);
            checkMandatoryField("certLocatin", certLocation, linked.CertLocation);
            checkOptionalField("certIssuer", certIssuer, linked.CertIssuer);
            checkOptionalField("caCerts", caCerts, linked.CACerts);
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
