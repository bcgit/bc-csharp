using System;
using System.Collections;

using NUnit.Framework;

namespace Org.BouncyCastle.Tls.Tests
{
    [TestFixture]
    public class TlsUtilitiesTest
    {
        [Test]
        public void TestChooseSignatureAndHash()
        {
            int keyExchangeAlgorithm = KeyExchangeAlgorithm.ECDHE_RSA;
            short signatureAlgorithm = TlsUtilities.GetLegacySignatureAlgorithmServer(keyExchangeAlgorithm);

            IList supportedSignatureAlgorithms = GetSignatureAlgorithms(false);
            SignatureAndHashAlgorithm sigAlg = TlsUtilities.ChooseSignatureAndHashAlgorithm(ProtocolVersion.TLSv12,
                supportedSignatureAlgorithms, signatureAlgorithm);
            Assert.AreEqual(HashAlgorithm.sha256, sigAlg.Hash);

            for (int count = 0; count < 10; ++count)
            {
                supportedSignatureAlgorithms = GetSignatureAlgorithms(true);
                sigAlg = TlsUtilities.ChooseSignatureAndHashAlgorithm(ProtocolVersion.TLSv12,
                    supportedSignatureAlgorithms, signatureAlgorithm);
                Assert.AreEqual(HashAlgorithm.sha256, sigAlg.Hash);
            }
        }

        private static IList GetSignatureAlgorithms(bool randomise)
        {
            short[] hashAlgorithms = new short[]{ HashAlgorithm.sha1, HashAlgorithm.sha224, HashAlgorithm.sha256,
                HashAlgorithm.sha384, HashAlgorithm.sha512, HashAlgorithm.md5 };
            short[] signatureAlgorithms = new short[]{ SignatureAlgorithm.rsa, SignatureAlgorithm.dsa,
                SignatureAlgorithm.ecdsa };

            IList result = new ArrayList();
            for (int i = 0; i < signatureAlgorithms.Length; ++i)
            {
                for (int j = 0; j < hashAlgorithms.Length; ++j)
                {
                    result.Add(SignatureAndHashAlgorithm.GetInstance(hashAlgorithms[j], signatureAlgorithms[i]));
                }
            }

            if (randomise)
            {
                Random r = new Random();
                int count = result.Count;
                for (int src = 0; src < count; ++src)
                {
                    int dst = r.Next(count);
                    if (src != dst)
                    {
                        object a = result[src], b = result[dst];
                        result[dst] = a;
                        result[src] = b;
                    }
                }
            }

            return result;
        }
    }
}
