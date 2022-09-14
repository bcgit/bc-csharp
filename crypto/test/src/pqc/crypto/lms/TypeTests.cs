using System;

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

            //todo
            // {
            //     Object o = new HSSPrivateKeyParameters(0,
            //         new ArrayList(new LMSPrivateKeyParameters(LMSigParameters.lms_sha256_n32_h5, null, 0, null, 0, new byte[32])),
            //         new ArrayList(dummySig), 1, 2);
            //     Assert.True(o.Equals(HSSPrivateKeyParameters.GetInstance(o)));
            // }

            {
                Object o = new HSSPublicKeyParameters(0, null);
                Assert.True(o.Equals(HSSPublicKeyParameters.GetInstance(o)));
            }

            {
                Object o = new HSSSignature(0, null, null);
                Assert.True(o.Equals(HSSSignature.GetInstance(o, 0)));
            }

            {
                Object o = new LMOtsPublicKey(null, null, 0, null);
                Assert.True(o.Equals(LMOtsPublicKey.GetInstance(o)));
            }

            {
                Object o = new LMOtsSignature(null, null, null);
                Assert.True(o.Equals(LMOtsSignature.GetInstance(o)));
            }

            {
                Object o = new LMSPrivateKeyParameters(LMSigParameters.lms_sha256_n32_h5, null, 0, null, 0, null);
                Assert.True(o.Equals(LMSPrivateKeyParameters.GetInstance(o)));
            }

            {
                Object o = new LMSPublicKeyParameters(null, null, null, null);
                Assert.True(o.Equals(LMSPublicKeyParameters.GetInstance(o)));
            }

            {
                Object o = new LMSSignature(0, null, null, null);
                Assert.True(o.Equals(LMSSignature.GetInstance(o)));
            }

        }
    }
}
