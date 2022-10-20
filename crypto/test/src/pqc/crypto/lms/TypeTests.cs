using System.Collections.Generic;

using NUnit.Framework;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
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
            LMSSignature dummySig = new LMSSignature(0, null, null, null);

            {
                var keys = new List<LMSPrivateKeyParameters>();
                keys.Add(new LMSPrivateKeyParameters(LMSigParameters.lms_sha256_n32_h5, null, 0, null, 0, new byte[32]));

                var sig = new List<LMSSignature>();
                sig.Add(dummySig);

                object o = new HSSPrivateKeyParameters(0, keys, sig, 1, 2);
                Assert.True(o.Equals(HSSPrivateKeyParameters.GetInstance(o)));
            }

            {
                object o = new HSSPublicKeyParameters(0, null);
                Assert.True(o.Equals(HSSPublicKeyParameters.GetInstance(o)));
            }

            {
                object o = new HSSSignature(0, null, null);
                Assert.True(o.Equals(HSSSignature.GetInstance(o, 0)));
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
                object o = new LMSPrivateKeyParameters(LMSigParameters.lms_sha256_n32_h5, null, 0, null, 0, null);
                Assert.True(o.Equals(LMSPrivateKeyParameters.GetInstance(o)));
            }

            {
                object o = new LMSPublicKeyParameters(null, null, null, null);
                Assert.True(o.Equals(LMSPublicKeyParameters.GetInstance(o)));
            }

            {
                object o = new LMSSignature(0, null, null, null);
                Assert.True(o.Equals(LMSSignature.GetInstance(o)));
            }
        }
    }
}
