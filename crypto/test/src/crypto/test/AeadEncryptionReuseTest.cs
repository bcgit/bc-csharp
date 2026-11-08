using System;
using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Tests
{
    /// <summary>
    /// Once an encryption has used a key and nonce, a second message on the same instance without a new Init would
    /// be encrypted under the same nonce (for the CTR based modes, the same keystream). CCM, KCCM, EAX and OCB now
    /// refuse that, as GcmBlockCipher and ChaCha20Poly1305 already did; decryption stays reusable.
    /// </summary>
    [TestFixture]
    public class AeadEncryptionReuseTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        public sealed class Case
        {
            internal readonly string Name;
            internal readonly Func<IAeadCipher> Create;
            internal readonly int KeySize, NonceSize;
            internal readonly bool Streaming;

            internal Case(string name, Func<IAeadCipher> create, int keySize, int nonceSize, bool streaming)
            {
                Name = name;
                Create = create;
                KeySize = keySize;
                NonceSize = nonceSize;
                Streaming = streaming;
            }

            public override string ToString() => Name;
        }

        private static IEnumerable<Case> Cases()
        {
            yield return new Case("CCM", () => new CcmBlockCipher(AesUtilities.CreateEngine()), 16, 12, false);
            yield return new Case("KCCM", () => new KCcmBlockCipher(new Dstu7624Engine(128)), 16, 16, false);
            yield return new Case("EAX", () => new EaxBlockCipher(AesUtilities.CreateEngine()), 16, 12, true);
            yield return new Case("OCB",
                () => new OcbBlockCipher(AesUtilities.CreateEngine(), AesUtilities.CreateEngine()), 16, 12, true);
        }

        private static IEnumerable<Case> StreamingCases()
        {
            foreach (Case c in Cases())
            {
                if (c.Streaming)
                    yield return c;
            }
        }

        [TestCaseSource(nameof(Cases))]
        public void SecondEncryptionWithoutInitIsRefused(Case c)
        {
            IAeadCipher cipher = c.Create();
            cipher.Init(true, Parameters(c, RandomBytes(c.KeySize), RandomBytes(c.NonceSize)));

            Encrypt(cipher, RandomBytes(32));

            var e = Assert.Throws<InvalidOperationException>(() => Encrypt(cipher, RandomBytes(32)), c.Name);
            StringAssert.Contains("cannot be reused for encryption", e.Message, c.Name);

            // and still refused after Reset(), which does not choose a new nonce
            cipher.Reset();
            Assert.Throws<InvalidOperationException>(() => Encrypt(cipher, RandomBytes(32)), c.Name);
        }

#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        [TestCaseSource(nameof(Cases))]
        public void SecondEncryptionWithoutInitIsRefused_Span(Case c)
        {
            IAeadCipher cipher = c.Create();
            cipher.Init(true, Parameters(c, RandomBytes(c.KeySize), RandomBytes(c.NonceSize)));

            byte[] input = RandomBytes(32);
            byte[] output = new byte[cipher.GetOutputSize(input.Length)];
            int len = cipher.ProcessBytes(input.AsSpan(), output.AsSpan());
            cipher.DoFinal(output.AsSpan(len));

            Assert.Throws<InvalidOperationException>(() =>
            {
                byte[] output2 = new byte[cipher.GetOutputSize(input.Length)];
                int len2 = cipher.ProcessBytes(input.AsSpan(), output2.AsSpan());
                cipher.DoFinal(output2.AsSpan(len2));
            }, c.Name);
        }
#endif

        [Test]
        public void CcmSecondProcessPacketIsRefused()
        {
            var cipher = new CcmBlockCipher(AesUtilities.CreateEngine());
            cipher.Init(true, new AeadParameters(new KeyParameter(RandomBytes(16)), 128, RandomBytes(12)));

            cipher.ProcessPacket(RandomBytes(32), 0, 32);

            Assert.Throws<InvalidOperationException>(() => cipher.ProcessPacket(RandomBytes(32), 0, 32));
        }

        [TestCaseSource(nameof(Cases))]
        public void InitWithNewNonceAllowsEncryption(Case c)
        {
            byte[] key = RandomBytes(c.KeySize);
            IAeadCipher cipher = c.Create();
            cipher.Init(true, Parameters(c, key, RandomBytes(c.NonceSize)));
            Encrypt(cipher, RandomBytes(32));

            byte[] nonce = RandomBytes(c.NonceSize), message = RandomBytes(32);
            cipher.Init(true, Parameters(c, key, nonce));
            byte[] ciphertext = Encrypt(cipher, message);

            IAeadCipher decryptor = c.Create();
            decryptor.Init(false, Parameters(c, key, nonce));
            Assert.IsTrue(Arrays.AreEqual(message, Decrypt(decryptor, ciphertext)), c.Name);
        }

        [TestCaseSource(nameof(Cases))]
        public void ResetBeforeAnyDataStillAllowsEncryption(Case c)
        {
            IAeadCipher cipher = c.Create();
            cipher.Init(true, Parameters(c, RandomBytes(c.KeySize), RandomBytes(c.NonceSize)));

            cipher.Reset();
            Encrypt(cipher, RandomBytes(32));
        }

        [TestCaseSource(nameof(StreamingCases))]
        public void ResetAfterStreamedDataUsesTheNonce(Case c)
        {
            IAeadCipher cipher = c.Create();
            cipher.Init(true, Parameters(c, RandomBytes(c.KeySize), RandomBytes(c.NonceSize)));

            // a partial message has already produced ciphertext under the nonce
            byte[] output = new byte[64];
            cipher.ProcessBytes(RandomBytes(48), 0, 48, output, 0);
            cipher.Reset();

            Assert.Throws<InvalidOperationException>(() => Encrypt(cipher, RandomBytes(32)), c.Name);
        }

        [TestCaseSource(nameof(Cases))]
        public void DecryptionIsStillReusable(Case c)
        {
            byte[] key = RandomBytes(c.KeySize), nonce = RandomBytes(c.NonceSize), message = RandomBytes(32);

            IAeadCipher encryptor = c.Create();
            encryptor.Init(true, Parameters(c, key, nonce));
            byte[] ciphertext = Encrypt(encryptor, message);

            IAeadCipher decryptor = c.Create();
            decryptor.Init(false, Parameters(c, key, nonce));
            Assert.IsTrue(Arrays.AreEqual(message, Decrypt(decryptor, ciphertext)), c.Name);
            Assert.IsTrue(Arrays.AreEqual(message, Decrypt(decryptor, ciphertext)), c.Name);
        }

        private static byte[] Encrypt(IAeadCipher cipher, byte[] input)
        {
            byte[] output = new byte[cipher.GetOutputSize(input.Length)];
            int len = cipher.ProcessBytes(input, 0, input.Length, output, 0);
            len += cipher.DoFinal(output, len);
            return Arrays.CopyOf(output, len);
        }

        private static byte[] Decrypt(IAeadCipher cipher, byte[] input)
        {
            byte[] output = new byte[cipher.GetOutputSize(input.Length)];
            int len = cipher.ProcessBytes(input, 0, input.Length, output, 0);
            len += cipher.DoFinal(output, len);
            return Arrays.CopyOf(output, len);
        }

        private static ICipherParameters Parameters(Case c, byte[] key, byte[] nonce) =>
            new AeadParameters(new KeyParameter(key), 128, nonce);

        private static byte[] RandomBytes(int length)
        {
            byte[] bytes = new byte[length];
            Random.NextBytes(bytes);
            return bytes;
        }
    }
}
