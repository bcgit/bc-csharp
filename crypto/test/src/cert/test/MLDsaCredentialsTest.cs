using NUnit.Framework;

namespace Org.BouncyCastle.Cert.Tests
{
    [TestFixture]
    public class MLDsaCredentialsTest
    {
        [Test]
        public void Sample_ML_DSA_44()
        {
            CheckSampleCredentials(SampleCredentials.ML_DSA_44);
        }

        [Test]
        public void Sample_ML_DSA_65()
        {
            CheckSampleCredentials(SampleCredentials.ML_DSA_65);
        }

        [Test]
        public void Sample_ML_DSA_87()
        {
            CheckSampleCredentials(SampleCredentials.ML_DSA_87);
        }

        private static void CheckSampleCredentials(SampleCredentials creds)
        {
            var cert = creds.Certificate;
            cert.Verify(cert.GetPublicKey());
        }
    }
}
