using System;
using System.Collections.Generic;
using System.Threading;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>
    /// Every WOTS+ one-time key may sign once only (RFC 8391 sec. 1.1): threads racing on one key, a state shared
    /// between two keys, and a key rebuilt around a state that has already signed must none of them sign twice at
    /// one index.
    /// </summary>
    /// <remarks>
    /// The XMSS methods, and the XMSS half of <see cref="TestSignatureMarksTheOneTimeKeyItSpent"/>. The XMSS^MT
    /// methods and half arrive with the XMSS^MT keys.
    /// </remarks>
    [TestFixture]
    public class OneTimeKeyReuseTests
    {
        private const int Height = 4;
        private const int Threads = 4;
        private const int Trials = 8;

        /// <summary>
        /// The signatures produced by a set of threads racing on one key, ignoring the threads that failed - a
        /// signature that was never produced spends nothing.
        /// </summary>
        private static List<KeyValuePair<byte[], byte[]>> Sign(XmssPrivateKeyParameters privKey)
        {
            List<KeyValuePair<byte[], byte[]>> sigs = new List<KeyValuePair<byte[], byte[]>>();
            Thread[] threads = new Thread[Threads];

            for (int i = 0; i != Threads; i++)
            {
                byte[] message = new byte[]{ (byte)i, 0x5a };

                threads[i] = new Thread(() =>
                {
                    byte[] sig;
                    try
                    {
                        sig = XmssEngine.GenerateSignature(privKey, message);
                    }
                    catch (Exception)
                    {
                        // key exhausted, or this thread lost the race: nothing was spent
                        return;
                    }

                    lock (sigs)
                    {
                        sigs.Add(new KeyValuePair<byte[], byte[]>(message, sig));
                    }
                });
            }

            for (int i = 0; i != Threads; i++)
            {
                threads[i].Start();
            }
            for (int i = 0; i != Threads; i++)
            {
                threads[i].Join();
            }

            return sigs;
        }

        [Test]
        public void TestXmssConcurrentSigningSpendsEachOneTimeKeyOnce()
        {
            for (int trial = 0; trial != Trials; trial++)
            {
                XmssParameters parameters = new XmssParameters(Height, new Sha256Digest());
                XmssKeyPairGenerator kpg = new XmssKeyPairGenerator();

                kpg.Init(new XmssKeyGenerationParameters(new SecureRandom(), parameters));

                AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();
                XmssPrivateKeyParameters privKey = (XmssPrivateKeyParameters)kp.Private;
                XmssPublicKeyParameters pubKey = (XmssPublicKeyParameters)kp.Public;

                List<KeyValuePair<byte[], byte[]>> sigs = Sign(privKey);
                HashSet<int> seen = new HashSet<int>();

                foreach (KeyValuePair<byte[], byte[]> pair in sigs)
                {
                    // only a signature that verifies represents a one-time key that was actually spent
                    if (!XmssEngine.VerifySignature(pubKey, pair.Key, pair.Value))
                    {
                        continue;
                    }

                    // an XMSS signature leads with its 4-byte big-endian index (RFC 8391 sec. 4.1.8)
                    int index = XmssHarnessTests.IndexOf(pair.Value);

                    Assert.IsTrue(seen.Add(index), "one-time key at index " + index + " signed twice");
                }

                Assert.AreEqual(Threads, seen.Count, "every thread signs, each at an index of its own");
            }
        }

        /// <summary>
        /// A signature records on the traversal state that its one-time key has signed. The record is only still
        /// there to see where the roll leaves that state in place: for XMSS the very last leaf, where the state is
        /// the exhausted key placeholder; everywhere else the roll installs a fresh state on a leaf that has not
        /// signed yet.
        /// </summary>
        /// <remarks>XMSS half: the XMSS^MT layer zero half arrives with the XMSS^MT keys.</remarks>
        [Test]
        public void TestSignatureMarksTheOneTimeKeyItSpent()
        {
            XmssParameters parameters = new XmssParameters(Height, new Sha256Digest());
            XmssKeyPairGenerator kpg = new XmssKeyPairGenerator();

            kpg.Init(new XmssKeyGenerationParameters(new SecureRandom(), parameters));

            XmssPrivateKeyParameters key = (XmssPrivateKeyParameters)kpg.GenerateKeyPair().Private;

            for (int i = 1; i <= (1 << Height); i++)
            {
                XmssEngine.GenerateSignature(key, new byte[]{ (byte)i });

                Assert.AreEqual(i == (1 << Height), key.GetBdsState().IsUsed, "XMSS after signature " + i);
            }
        }

        /// <summary>
        /// A signature marks the state it spent in place, so two keys sharing one BDS would share that record: the
        /// key signing would mark the state of the key that is not, which would then be refused as a key that has
        /// already signed. The builder copies the state it is given.
        /// </summary>
        [Test]
        public void TestXmssKeyBuilderCopiesTheTraversalStateItIsGiven()
        {
            XmssParameters parameters = new XmssParameters(Height, new Sha256Digest());
            XmssKeyPairGenerator kpg = new XmssKeyPairGenerator();

            kpg.Init(new XmssKeyGenerationParameters(new SecureRandom(), parameters));

            XmssPrivateKeyParameters key = (XmssPrivateKeyParameters)kpg.GenerateKeyPair().Private;
            XmssPrivateKeyParameters shard = new XmssPrivateKeyParameters.Builder(parameters)
                .WithSecretKeySeed(key.GetSecretKeySeed()).WithSecretKeyPrf(key.GetSecretKeyPrf())
                .WithPublicSeed(key.GetPublicSeed()).WithRoot(key.GetRoot())
                .WithBdsState(key.GetBdsState()).Build();

            Assert.AreNotSame(key.GetBdsState(), shard.GetBdsState(),
                "the builder must copy the state it is given, not adopt it");

            XmssEngine.GenerateSignature(key, new byte[]{ 0x01 });

            Assert.AreEqual(1, key.Index, "the other key's index moved");
            Assert.AreEqual(0, shard.Index, "the shard's index did not");
            Assert.IsFalse(shard.GetBdsState().IsUsed, "nor may the other key's signature mark the shard's state");

            // which is the point: a shard that has signed nothing must still be able to
            XmssEngine.GenerateSignature(shard, new byte[]{ 0x02 });
            Assert.AreEqual(1, shard.Index);
        }

        /// <summary>
        /// The used record travels with the state - it is copied by every state copy and written into the encoding
        /// - so a key can arrive holding a state that says it has already signed. Taking the traversal state off a
        /// live key and letting that key sign leaves the object taken marked; a key built back around it sits on
        /// the index the signature spent, and is refused.
        /// </summary>
        [Test]
        public void TestSigningIsRefusedOnAStateThatHasAlreadySigned()
        {
            XmssParameters parameters = new XmssParameters(Height, new Sha256Digest());
            XmssKeyPairGenerator kpg = new XmssKeyPairGenerator();

            kpg.Init(new XmssKeyGenerationParameters(new SecureRandom(), parameters));

            XmssPrivateKeyParameters key = (XmssPrivateKeyParameters)kpg.GenerateKeyPair().Private;
            Bds spent = key.GetBdsState();

            XmssEngine.GenerateSignature(key, new byte[]{ 0x01 });

            Assert.IsTrue(spent.IsUsed, "the signature must mark the state it spent");
            Assert.AreEqual(1, key.Index, "and roll the key past it");

            XmssPrivateKeyParameters rolledBack = new XmssPrivateKeyParameters.Builder(parameters)
                .WithSecretKeySeed(key.GetSecretKeySeed()).WithSecretKeyPrf(key.GetSecretKeyPrf())
                .WithPublicSeed(key.GetPublicSeed()).WithRoot(key.GetRoot())
                .WithBdsState(spent).Build();

            Assert.AreEqual(0, rolledBack.Index, "the rebuilt key is back on the index that signature spent");

            InvalidOperationException e = Assert.Throws<InvalidOperationException>(
                () => XmssEngine.GenerateSignature(rolledBack, new byte[]{ 0x02 }),
                "a state that has already signed must not sign again");
            Assert.AreEqual("one time key at index 0 has already signed", e.Message);
        }
    }
}
