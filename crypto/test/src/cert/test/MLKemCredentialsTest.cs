using NUnit.Framework;

namespace Org.BouncyCastle.Cert.Tests
{
    [TestFixture]
    public class MLKemCredentialsTest
    {
        [Test]
        public void Sample_ML_KEM_512()
        {
            CheckSampleCredentials(SampleCredentials.ML_KEM_512, SampleCredentials.ML_DSA_44);
        }

        [Test]
        public void Sample_ML_KEM_768()
        {
            CheckSampleCredentials(SampleCredentials.ML_KEM_768, SampleCredentials.ML_DSA_65);
        }

        [Test]
        public void Sample_ML_KEM_1024()
        {
            CheckSampleCredentials(SampleCredentials.ML_KEM_1024, SampleCredentials.ML_DSA_87);
        }

        private static void CheckSampleCredentials(SampleCredentials subject, SampleCredentials issuer)
        {
            subject.Certificate.Verify(issuer.Certificate.GetPublicKey());
        }
    }
}
