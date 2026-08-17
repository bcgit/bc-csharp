using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Tests
{
    [TestFixture]
    public class TlsUtilitiesTest
    {
        [Test]
        public void ChooseSignatureAndHash()
        {
            int keyExchangeAlgorithm = KeyExchangeAlgorithm.ECDHE_RSA;
            short signatureAlgorithm = TlsUtilities.GetLegacySignatureAlgorithmServer(keyExchangeAlgorithm);

            var supportedSignatureAlgorithms = GetSignatureAlgorithms(false);
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

        [Test]
        public void ReadFullyDoesNotAllocateFromDeclaredLength()
        {
            try
            {
                // 2^31-1 exceeds the VM array limit, so a pre-allocating readFully raises an Error here
                TlsUtilities.ReadFully(Arrays.MaxLength, new MemoryStream(new byte[8]));
                Assert.Fail("hostile length accepted");
            }
            catch (EndOfStreamException)
            {
                // expected: the stream runs out long before the declared length
            }
        }

        [Test]
        public void ReadFullyStillReadsExactly()
        {
            byte[] data = new byte[]{ 1, 2, 3, 4, 5, 6, 7, 8 };

            Assert.That(Arrays.AreEqual(data, TlsUtilities.ReadFully(8, new MemoryStream(data, false))));
            Assert.That(Arrays.AreEqual(new byte[]{ 1, 2, 3 },
                TlsUtilities.ReadFully(3, new MemoryStream(data, false))));
            Assert.AreEqual(0, TlsUtilities.ReadFully(0, new MemoryStream(data, false)).Length);

            byte[] opaque = new byte[]{ 0x00, 0x00, 0x03, 0x0a, 0x0b, 0x0c };
            Assert.That(Arrays.AreEqual(new byte[]{ 0x0a, 0x0b, 0x0c },
                TlsUtilities.ReadOpaque24(new MemoryStream(opaque, false))));
        }

        [Test]
        public void ReadOpaque24DoesNotAllocateFromDeclaredLength()
        {
            try
            {
                // 0xFFFFFF is only 16MB, so this one passed before the fix too - wire-path assertion only
                TlsUtilities.ReadOpaque24(new MemoryStream(new byte[]{ 0xFF, 0xFF, 0xFF }));
                Assert.Fail("hostile opaque24 length accepted");
            }
            catch (EndOfStreamException)
            {
                // expected
            }
        }

        private static IList<SignatureAndHashAlgorithm> GetSignatureAlgorithms(bool randomise)
        {
            short[] hashAlgorithms = new short[]{ HashAlgorithm.sha1, HashAlgorithm.sha224, HashAlgorithm.sha256,
                HashAlgorithm.sha384, HashAlgorithm.sha512, HashAlgorithm.md5 };
            short[] signatureAlgorithms = new short[]{ SignatureAlgorithm.rsa, SignatureAlgorithm.dsa,
                SignatureAlgorithm.ecdsa };

            var result = new List<SignatureAndHashAlgorithm>();
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
                        var a = result[src];
                        var b = result[dst];
                        result[dst] = a;
                        result[src] = b;
                    }
                }
            }

            return result;
        }
    }
}
