
using NUnit.Core;
using NUnit.Framework;
using Org.BouncyCastle.Bcpg.Sig;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    [TestFixture]
    public class PgpFeaturesTest
    {
        [Test]
        public void PerformTest()
        {
            Features f = new Features(true, Features.FEATURE_MODIFICATION_DETECTION);
            Assert.IsTrue(f.SupportsFeature(Features.FEATURE_MODIFICATION_DETECTION));
            Assert.IsTrue(f.SupportsModificationDetection);
            Assert.IsTrue(!f.SupportsFeature(Features.FEATURE_VERSION_5_PUBLIC_KEY));

            f = new Features(true, Features.FEATURE_VERSION_5_PUBLIC_KEY);
            Assert.IsTrue(!f.SupportsModificationDetection);
            Assert.IsTrue(f.SupportsFeature(Features.FEATURE_VERSION_5_PUBLIC_KEY));

            f = new Features(true, Features.FEATURE_AEAD_ENCRYPTED_DATA);
            Assert.IsTrue(f.SupportsFeature(Features.FEATURE_AEAD_ENCRYPTED_DATA));
            Assert.IsTrue(!f.SupportsModificationDetection);
            Assert.IsTrue(!f.SupportsFeature(Features.FEATURE_VERSION_5_PUBLIC_KEY));

            f = new Features(true, Features.FEATURE_AEAD_ENCRYPTED_DATA | Features.FEATURE_MODIFICATION_DETECTION);
            Assert.IsTrue(f.SupportsFeature(Features.FEATURE_AEAD_ENCRYPTED_DATA));
            Assert.IsTrue(f.SupportsModificationDetection);
            Assert.IsTrue(!f.SupportsFeature(Features.FEATURE_VERSION_5_PUBLIC_KEY));

            f = new Features(true, Features.FEATURE_VERSION_5_PUBLIC_KEY | Features.FEATURE_MODIFICATION_DETECTION);
            Assert.IsTrue(!f.SupportsFeature(Features.FEATURE_AEAD_ENCRYPTED_DATA));
            Assert.IsTrue(f.SupportsModificationDetection);
            Assert.IsTrue(f.SupportsFeature(Features.FEATURE_VERSION_5_PUBLIC_KEY));
        }

        public static void Main(string[] args)
        {
            Suite.Run(new NullListener(), NUnit.Core.TestFilter.Empty);
        }

        [Suite]
        public static TestSuite Suite
        {
            get
            {
                TestSuite suite = new TestSuite("PGP Features Tests");
                suite.Add(new PgpFeaturesTest());
                return suite;
            }
        }
    }
}
