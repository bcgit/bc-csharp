using System;
using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Tests
{
    /// <summary>
    /// After a decryption fails its tag check, GetMac() must not return the tag the cipher computed for the rejected
    /// input: that is the valid tag for the attacker's ciphertext and associated data, so a caller that logs or returns
    /// GetMac() after the InvalidCipherTextException would hand out a forgery.
    /// </summary>
    [TestFixture]
    public class AeadFailedDecryptionMacTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        public sealed class Case
        {
            internal readonly string Name;
            internal readonly Func<IAeadCipher> Create;
            internal readonly int KeySize, NonceSize, MacSize;
            internal readonly bool IVOnly;

            internal Case(string name, Func<IAeadCipher> create, int keySize, int nonceSize, int macSize,
                bool ivOnly = false)
            {
                Name = name;
                Create = create;
                KeySize = keySize;
                NonceSize = nonceSize;
                MacSize = macSize;
                IVOnly = ivOnly;
            }

            public override string ToString() => Name;
        }

        private static IEnumerable<Case> Cases()
        {
            yield return new Case("GCM", () => new GcmBlockCipher(AesUtilities.CreateEngine()), 16, 12, 16);
            yield return new Case("ChaCha20Poly1305", () => new ChaCha20Poly1305(), 32, 12, 16);
            yield return new Case("XChaCha20Poly1305", () => new XChaCha20Poly1305(), 32, 24, 16);
            yield return new Case("EAX", () => new EaxBlockCipher(AesUtilities.CreateEngine()), 16, 12, 16);
            yield return new Case("OCB",
                () => new OcbBlockCipher(AesUtilities.CreateEngine(), AesUtilities.CreateEngine()), 16, 12, 16);
            yield return new Case("Sparkle",
                () => new SparkleEngine(SparkleEngine.SparkleParameters.SCHWAEMM128_128), 16, 16, 16);
            yield return new Case("Grain128AEAD", () => new Grain128AeadEngine(), 16, 12, 8, ivOnly: true);
        }

        [TestCaseSource(nameof(Cases))]
        public void GetMacAfterFailedDecryptionIsNotAValidTag(Case c)
        {
            byte[] key = RandomBytes(c.KeySize), nonce = RandomBytes(c.NonceSize);
            byte[] forged = RandomBytes(32 + c.MacSize);

            byte[] mac = DecryptExpectingFailure(c, key, nonce, forged, useSpan: false);
            AssertNotAValidTag(c, key, nonce, forged, mac);
        }

#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        [TestCaseSource(nameof(Cases))]
        public void GetMacAfterFailedDecryptionIsNotAValidTag_Span(Case c)
        {
            byte[] key = RandomBytes(c.KeySize), nonce = RandomBytes(c.NonceSize);
            byte[] forged = RandomBytes(32 + c.MacSize);

            byte[] mac = DecryptExpectingFailure(c, key, nonce, forged, useSpan: true);
            AssertNotAValidTag(c, key, nonce, forged, mac);
        }
#endif

        private static byte[] DecryptExpectingFailure(Case c, byte[] key, byte[] nonce, byte[] input, bool useSpan)
        {
            IAeadCipher cipher = c.Create();
            cipher.Init(false, Parameters(c, key, nonce));

            byte[] output = new byte[cipher.GetOutputSize(input.Length) + 64];
            int len = cipher.ProcessBytes(input, 0, input.Length, output, 0);

#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            if (useSpan)
            {
                Assert.Throws<InvalidCipherTextException>(() => cipher.DoFinal(output.AsSpan(len)), c.Name);
                return cipher.GetMac();
            }
#endif
            Assert.Throws<InvalidCipherTextException>(() => cipher.DoFinal(output, len), c.Name);
            return cipher.GetMac();
        }

        private static void AssertNotAValidTag(Case c, byte[] key, byte[] nonce, byte[] forged, byte[] mac)
        {
            if (mac == null)
                return;

            Assert.AreEqual(c.MacSize, mac.Length, c.Name);

            // put what GetMac() returned in place of the tag: the result must still be rejected
            byte[] retagged = (byte[])forged.Clone();
            Array.Copy(mac, 0, retagged, retagged.Length - c.MacSize, c.MacSize);

            IAeadCipher cipher = c.Create();
            cipher.Init(false, Parameters(c, key, nonce));
            byte[] output = new byte[cipher.GetOutputSize(retagged.Length) + 64];
            int len = cipher.ProcessBytes(retagged, 0, retagged.Length, output, 0);
            Assert.Throws<InvalidCipherTextException>(() => cipher.DoFinal(output, len), c.Name);
        }

        private static ICipherParameters Parameters(Case c, byte[] key, byte[] nonce)
        {
            if (c.IVOnly)
                return new ParametersWithIV(new KeyParameter(key), nonce);

            return new AeadParameters(new KeyParameter(key), c.MacSize * 8, nonce);
        }

        private static byte[] RandomBytes(int length)
        {
            byte[] bytes = new byte[length];
            Random.NextBytes(bytes);
            return bytes;
        }
    }
}
