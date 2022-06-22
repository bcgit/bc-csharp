using System;

using NUnit.Framework;

using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    [TestFixture]
    public class PgpFeaturesTest
        : SimpleTest
    {
        public override void PerformTest()
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

        public override string Name
        {
            get { return "PgpFeaturesTest"; }
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
