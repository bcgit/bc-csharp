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
        public override string Name
        {
            get { return "LinkedCertificate"; }
        }

        public override void PerformTest()
        {
            DigestInfo digInfo = new DigestInfo(new AlgorithmIdentifier(NistObjectIdentifiers.IdSha256), new byte[32]);
            GeneralName certLocation = new GeneralName(GeneralName.UniformResourceIdentifier, "https://www.bouncycastle.org/certs");
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
                Fail("null getInstance() failed.");
            }

            try
            {
                LinkedCertificate.GetInstance(new object());

                Fail("getInstance() failed to detect bad object.");
            }
            catch (ArgumentException e)
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

            Asn1InputStream aIn = new Asn1InputStream(linked.ToAsn1Object().GetEncoded());

            Asn1Sequence seq = (Asn1Sequence)aIn.ReadObject();

            linked = LinkedCertificate.GetInstance(seq);

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

        public static void MainOld(string[] args)
        {
            RunTest(new LinkedCertificateTest());
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
