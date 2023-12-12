using System.Collections.Generic;

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
                var keys = new List<LmsPrivateKeyParameters>();
                keys.Add(new LmsPrivateKeyParameters(LMSigParameters.lms_sha256_n32_h5, null, 0, null, 0, new byte[32]));

                var sig = new List<LmsSignature>();
                sig.Add(dummySig);

                object o = new HssPrivateKeyParameters(0, keys, sig, 1, 2);
                Assert.True(o.Equals(HssPrivateKeyParameters.GetInstance(o)));
            }

            {
                object o = new HssPublicKeyParameters(0, new LmsPublicKeyParameters(null, null, null, null));
                Assert.True(o.Equals(HssPublicKeyParameters.GetInstance(o)));
            }

            {
                object o = new HssSignature(0, null, null);
                Assert.True(o.Equals(HssSignature.GetInstance(o, 0)));
            }

            {
                object o = new LMOtsPublicKey(null, null, 0, null);
                Assert.True(o.Equals(LMOtsPublicKey.GetInstance(o)));
            }

            {
                object o = new LMOtsSignature(null, null, null);
                Assert.True(o.Equals(LMOtsSignature.GetInstance(o)));
            }

            {
                object o = new LmsPrivateKeyParameters(LMSigParameters.lms_sha256_n32_h5, null, 0, null, 0, null);
                Assert.True(o.Equals(LmsPrivateKeyParameters.GetInstance(o)));
            }

            {
                object o = new LmsPublicKeyParameters(null, null, null, null);
                Assert.True(o.Equals(LmsPublicKeyParameters.GetInstance(o)));
            }

            {
                object o = new LmsSignature(0, null, null, null);
                Assert.True(o.Equals(LmsSignature.GetInstance(o)));
            }
        }
    }
}
