using NUnit.Framework;

namespace Org.BouncyCastle.Pqc.Crypto.Lms.Tests
{
    [TestFixture]
    public class TypeTests
    {
        /**
        * Get instance methods are expected to return the instance passed to them if it is the same type.
        *
        * @throws Exception
        */
        [Test]
        public void TestTypeForType()
        {
            LmsSignature dummySig = new LmsSignature(0, null, null, null);

            {
                object o = new HssPrivateKeyParameters(LmsKey(), 1, 2);
                Assert.AreSame(o, HssPrivateKeyParameters.GetInstance(o));
            }

            {
                object o = new HssPublicKeyParameters(0, LmsPublicKey());
                Assert.AreSame(o, HssPublicKeyParameters.GetInstance(o));
            }

            {
                object o = new HssSignature(0, null, null);
                Assert.AreSame(o, HssSignature.GetInstance(o, 0));
            }

            {
                object o = new LMOtsPublicKey(null, null, 0, null);
                Assert.AreSame(o, LMOtsPublicKey.GetInstance(o));
            }

            {
                object o = new LMOtsSignature(null, null, null);
                Assert.AreSame(o, LMOtsSignature.GetInstance(o));
            }

            {
                object o = LmsKey();
                Assert.AreSame(o, LmsPrivateKeyParameters.GetInstance(o));
            }

            {
                object o = LmsPublicKey();
                Assert.AreSame(o, LmsPublicKeyParameters.GetInstance(o));
            }

            {
                object o = new LmsSignature(0, null, null, null);
                Assert.AreSame(o, LmsSignature.GetInstance(o));
            }
        }

        /// <summary>
        /// The key parameter constructors validate their arguments, so these are real -the point of the test is only
        /// that GetInstance() hands back an object of its own type unchanged.
        /// </summary>
        private static LmsPublicKeyParameters LmsPublicKey()
        {
            return new LmsPublicKeyParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1,
                null, null);
        }

        private static LmsPrivateKeyParameters LmsKey()
        {
            return new LmsPrivateKeyParameters(LMSigParameters.lms_sha256_n32_h5,
                LMOtsParameters.sha256_n32_w1, 0, new byte[16], 1 << LMSigParameters.lms_sha256_n32_h5.H,
                new byte[LMSigParameters.lms_sha256_n32_h5.M]);
        }
    }
}
