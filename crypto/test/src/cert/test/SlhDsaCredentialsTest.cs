using NUnit.Framework;

namespace Org.BouncyCastle.Cert.Tests
{
    [TestFixture]
    public class SlhDsaCredentialsTest
    {
        [Test]
        public void Sample_SLH_DSA_SHA2_128S()
        {
            CheckSampleCredentials(SampleCredentials.SLH_DSA_SHA2_128S);
        }

        private static void CheckSampleCredentials(SampleCredentials creds)
        {
            var cert = creds.Certificate;
            cert.Verify(cert.GetPublicKey());
        }
    }
}
