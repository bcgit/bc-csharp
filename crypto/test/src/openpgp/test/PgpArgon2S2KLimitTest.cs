using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>
    /// An OpenPGP Argon2 S2K specifier carries attacker-chosen passes, parallelism and memory - size fields that are
    /// honoured (Argon2 is run) before the message can be authenticated.
    /// </summary>
    /// <remarks>
    /// Key derivation must clamp all three so a single decrypt attempt cannot be driven into a huge allocation (~1 TiB)
    /// or unbounded CPU work; legitimate, in-range parameters must still derive a key.
    /// </remarks>
    [TestFixture]
    public class PgpArgon2S2KLimitTest
    {
        private static readonly byte[] Salt = new byte[16];

        private static S2k Argon2(int passes, int parallelism, int memExp) =>
            new S2k(new S2k.Argon2Params(Salt, passes, parallelism, memExp));

        private void AssertRejected(S2k s2k, string fragment)
        {
            try
            {
                PgpUtilities.MakeKeyFromPassPhrase(SymmetricKeyAlgorithmTag.Aes256, s2k, "password".ToCharArray());
                Assert.Fail($"excessive Argon2 cost accepted ({fragment})");
            }
            catch (PgpException e)
            {
                //assertTrue("unexpected message: " + e.getMessage(), e.getMessage().indexOf(fragment) >= 0);
                bool debug = true;
            }
        }

        [Test]
        public void ExcessiveArgon2CostRejected()
        {
            // memExp 30 -> memory = 2^30 KiB = 2^40 bytes = 1 TiB of Argon2 working memory
            AssertRejected(Argon2(1, 1, 30), "memory size exponent out of range");
            AssertRejected(Argon2(255, 1, 16), "passes out of range");
            AssertRejected(Argon2(1, 255, 16), "parallelism out of range");
        }

        [Test]
        public void InRangeArgon2Accepted()
        {
            // memExp 16 -> memory = 2^16 KiB = 64 MiB, 1 pass, 1 lane: within the caps, key derived normally
            //byte[] key = factory().makeKeyFromPassPhrase(SymmetricKeyAlgorithmTags.AES_256, Argon2(1, 1, 16));
            KeyParameter key = PgpUtilities.MakeKeyFromPassPhrase(SymmetricKeyAlgorithmTag.Aes256, Argon2(1, 1, 16),
                "password".ToCharArray());
            Assert.AreEqual(32, key.KeyLength);
        }
    }
}
