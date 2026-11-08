using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>
    /// An XMSS^MT private key of a non-standard parameter set is written in the legacy ASN.1 form, whose index is a
    /// long the whole way. A tree taller than 32 needs more than four bytes for it, and narrowing it to an int on the
    /// way through would wrap an out-of-range value into an in-range one: the key would be exported claiming a
    /// position it had already signed past, and re-importing it would reuse every one-time key in between
    /// (RFC 8391 sec. 1.1).
    /// </summary>
    [TestFixture]
    public class LargeIndexEncodingTests
    {
        /// <summary>
        /// Total height 36 with 4 layers: 9 per layer, well inside the BDS limit, but not one of the RFC 8391
        /// sec. 5.4 registered sets - so it has no parameter-set OID and is encoded in the legacy form rather than the
        /// RFC 9802 raw form. ceil(36/8) = 5 index bytes.
        /// </summary>
        private const int Height = 36;
        private const int Layers = 4;

        private static XmssMTPrivateKeyParameters KeyAtIndex(XmssMTParameters parameters, long index)
        {
            int n = parameters.TreeDigestSize;
            byte[] secretKeySeed = new byte[n];
            byte[] secretKeyPrf = new byte[n];
            byte[] publicSeed = new byte[n];
            byte[] root = new byte[n];

            for (int i = 0; i != n; i++)
            {
                secretKeySeed[i] = (byte)i;
                secretKeyPrf[i] = (byte)(i + 1);
                publicSeed[i] = (byte)(i + 2);
                root[i] = (byte)(i + 3);
            }

            return new XmssMTPrivateKeyParameters.Builder(parameters)
                .WithIndex(index)
                .WithSecretKeySeed(secretKeySeed).WithSecretKeyPrf(secretKeyPrf)
                .WithPublicSeed(publicSeed).WithRoot(root)
                .WithBdsState(new BdsStateMap((1L << Height) - 1)).Build();
        }

        [Test]
        public void TestIndexBeyondIntRangeSurvivesEncoding()
        {
            XmssMTParameters parameters = new XmssMTParameters(Height, Layers, NistObjectIdentifiers.IdSha256);

            Assert.AreEqual(0, parameters.ParameterSetOid, "expected a non-standard parameter set");

            // just past what four bytes can hold: truncation reported this key as index 5
            long index = (1L << 32) + 5;

            XmssMTPrivateKeyParameters privKey = KeyAtIndex(parameters, index);
            PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privKey);
            XmssMTPrivateKeyParameters decoded = (XmssMTPrivateKeyParameters)PrivateKeyFactory.CreateKey(info);

            Assert.AreEqual(index, decoded.Index, "key rolled back by encoding");
        }

        /// <summary>
        /// The boundary itself, and the indices either side of it: 2^32 - 1 is the largest value four bytes hold, and
        /// the truncation showed up from 2^32 on.
        /// </summary>
        [Test]
        public void TestIndicesAroundTheFourByteBoundary()
        {
            XmssMTParameters parameters = new XmssMTParameters(Height, Layers, NistObjectIdentifiers.IdSha256);

            long[] indices = new long[]{
                0L,
                1L << 31,
                (1L << 32) - 1,
                1L << 32,
                1L << 35,
                (1L << Height) - 1 };

            for (int i = 0; i != indices.Length; i++)
            {
                XmssMTPrivateKeyParameters privKey = KeyAtIndex(parameters, indices[i]);
                PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privKey);
                XmssMTPrivateKeyParameters decoded = (XmssMTPrivateKeyParameters)PrivateKeyFactory.CreateKey(info);

                Assert.AreEqual(indices[i], decoded.Index, "index " + indices[i] + " did not survive encoding");
            }
        }
    }
}
