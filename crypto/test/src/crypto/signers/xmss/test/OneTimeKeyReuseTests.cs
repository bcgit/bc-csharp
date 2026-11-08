using System;
using System.Collections.Generic;
using System.Threading;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>
    /// Every WOTS+ one-time key may sign once only (RFC 8391 sec. 1.1): threads racing on one key, a state shared
    /// between two keys, and a key rebuilt around a state that has already signed must none of them sign twice at
    /// one index.
    /// </summary>
    /// <remarks>
    /// The engine's signature methods are reachable without a signer, so they take the lock on the key themselves;
    /// these drive them directly, the way a caller using the lightweight API would.
    /// </remarks>
    [TestFixture]
    public class OneTimeKeyReuseTests
    {
        private const int Height = 4;
        private const int Layers = 2;
        private const int Threads = 4;
        private const int Trials = 8;

        /// <summary>
        /// The signatures produced by a set of threads racing on one key, ignoring the threads that failed - a
        /// signature that was never produced spends nothing.
        /// </summary>
        private static List<KeyValuePair<byte[], byte[]>> Sign(XmssPrivateKeyParameters privKey) =>
            Sign(message => XmssEngine.GenerateSignature(privKey, message));

        private static List<KeyValuePair<byte[], byte[]>> Sign(XmssMTPrivateKeyParameters privKey) =>
            Sign(message => XmssEngine.GenerateMTSignature(privKey, message));

        private static List<KeyValuePair<byte[], byte[]>> Sign(Func<byte[], byte[]> sign)
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
                        sig = sign(message);
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

        [Test]
        public void TestXmssMTConcurrentSigningSpendsEachOneTimeKeyOnce()
        {
            int indexSize = (Height + 7) / 8;

            for (int trial = 0; trial != Trials; trial++)
            {
                XmssMTParameters parameters = new XmssMTParameters(Height, Layers, new Sha256Digest());
                XmssMTKeyPairGenerator kpg = new XmssMTKeyPairGenerator();

                kpg.Init(new XmssMTKeyGenerationParameters(new SecureRandom(), parameters));

                AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();
                XmssMTPrivateKeyParameters privKey = (XmssMTPrivateKeyParameters)kp.Private;
                XmssMTPublicKeyParameters pubKey = (XmssMTPublicKeyParameters)kp.Public;

                List<KeyValuePair<byte[], byte[]>> sigs = Sign(privKey);
                HashSet<long> seen = new HashSet<long>();

                foreach (KeyValuePair<byte[], byte[]> pair in sigs)
                {
                    if (!XmssEngine.VerifyMTSignature(pubKey, pair.Key, pair.Value))
                    {
                        continue;
                    }

                    // an XMSS^MT signature leads with its ceil(h/8)-byte index (RFC 8391 sec. 4.2.5)
                    long index = (long)Pack.BE_To_UInt64_Low(pair.Value, 0, indexSize);

                    Assert.IsTrue(seen.Add(index), "one-time key at index " + index + " signed twice");
                }

                Assert.AreEqual(Threads, seen.Count, "every thread signs, each at an index of its own");
            }
        }

        /// <summary>
        /// A signature records on the traversal state that its one-time key has signed. The record is only still
        /// there to see where the roll leaves that state in place, which is the last leaf of a subtree: everywhere
        /// else the roll installs a fresh state, sitting on a leaf that has not signed yet. For XMSS the whole tree
        /// is the subtree, so that is the very last leaf, where the state is the exhausted key placeholder.
        /// </summary>
        [Test]
        public void TestSignatureMarksTheOneTimeKeyItSpent()
        {
            XmssMTParameters mtParams = new XmssMTParameters(Height, Layers, new Sha256Digest());
            XmssMTKeyPairGenerator mtKpg = new XmssMTKeyPairGenerator();

            mtKpg.Init(new XmssMTKeyGenerationParameters(new SecureRandom(), mtParams));

            XmssMTPrivateKeyParameters mtKey = (XmssMTPrivateKeyParameters)mtKpg.GenerateKeyPair().Private;
            int leaves = 1 << mtParams.XmssParameters.Height;

            for (int i = 1; i <= leaves; i++)
            {
                XmssEngine.GenerateMTSignature(mtKey, new byte[]{ (byte)i });

                Assert.AreEqual(i == leaves, mtKey.GetBdsState().Get(0).IsUsed,
                    "XMSS^MT layer zero after signature " + i);
            }

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

        /// <summary>
        /// The XMSS^MT counterpart of <see cref="TestSigningIsRefusedOnAStateThatHasAlreadySigned"/>, on the layer
        /// zero state - the one whose leaf signs the message.
        /// </summary>
        /// <remarks>
        /// The check makes the allowance <see cref="BdsStateMap.Validate(XmssMTParameters, long)"/> makes: on the
        /// first leaf of a subtree the signer builds layer zero fresh, so the marked state carried over from the end
        /// of the previous subtree is legitimate at that one position. Signing every leaf of a key, across every
        /// subtree boundary in it, covers that.
        /// </remarks>
        [Test]
        public void TestMTSigningIsRefusedOnALayerZeroStateThatHasAlreadySigned()
        {
            XmssMTParameters parameters = new XmssMTParameters(Height, Layers, new Sha256Digest());
            XmssMTPrivateKeyParameters key = MTKey(parameters);

            // one signature, so layer zero exists and sits somewhere other than a subtree boundary
            XmssEngine.GenerateMTSignature(key, new byte[]{ 0x01 });

            BdsStateMap spent = key.GetBdsState();

            XmssEngine.GenerateMTSignature(key, new byte[]{ 0x02 });

            Assert.IsTrue(spent.Get(0).IsUsed, "the signature must mark the layer zero state it spent");

            XmssMTPrivateKeyParameters rolledBack = new XmssMTPrivateKeyParameters.Builder(parameters)
                .WithSecretKeySeed(key.GetSecretKeySeed()).WithSecretKeyPrf(key.GetSecretKeyPrf())
                .WithPublicSeed(key.GetPublicSeed()).WithRoot(key.GetRoot())
                .WithIndex(1L).WithBdsState(spent).Build();

            InvalidOperationException e = Assert.Throws<InvalidOperationException>(
                () => XmssEngine.GenerateMTSignature(rolledBack, new byte[]{ 0x03 }),
                "a layer zero state that has already signed must not sign again");
            Assert.AreEqual("one time key at index 1 has already signed", e.Message);

            // and the allowance: a whole key signed through, across every subtree boundary in it
            XmssMTPrivateKeyParameters walked = MTKey(parameters);

            for (long i = 0; i != (1L << Height); i++)
            {
                Assert.AreEqual(i, walked.Index);
                XmssEngine.GenerateMTSignature(walked, new byte[]{ (byte)i });
            }
        }

        /// <summary>
        /// The leaf 0 allowance covers the marked state carried over from the last leaf of the previous subtree, and
        /// nothing else. A marked layer zero state at leaf 0 is the one the signature at leaf 0 spent, left in place
        /// by a roll that did not complete; built from it, a key is refused, and so is the same key read back from
        /// its encoding.
        /// </summary>
        [Test]
        public void TestMTSigningIsRefusedOnASpentLayerZeroStateAtLeafZero()
        {
            XmssMTParameters parameters = new XmssMTParameters(Height, Layers, new Sha256Digest());
            XmssMTPrivateKeyParameters key = MTKey(parameters);
            long boundary = 1L << parameters.XmssParameters.Height;

            for (long i = 0; i != boundary; i++)
            {
                XmssEngine.GenerateMTSignature(key, new byte[]{ (byte)i });
            }

            // the map the signature at the boundary installs a fresh layer zero into, signs from, and marks
            BdsStateMap spent = key.GetBdsState();

            XmssEngine.GenerateMTSignature(key, new byte[]{ 0x10 });

            Assert.AreEqual(0, spent.Get(0).Index, "the spent layer zero state sits at leaf 0");
            Assert.IsTrue(spent.Get(0).IsUsed, "and is marked");

            // the key as a roll that threw would have left it: at the boundary index, holding that map
            XmssMTPrivateKeyParameters stuck = new XmssMTPrivateKeyParameters.Builder(parameters)
                .WithSecretKeySeed(key.GetSecretKeySeed()).WithSecretKeyPrf(key.GetSecretKeyPrf())
                .WithPublicSeed(key.GetPublicSeed()).WithRoot(key.GetRoot())
                .WithIndex(boundary).WithBdsState(spent).Build();
            XmssMTPrivateKeyParameters restored = new XmssMTPrivateKeyParameters.Builder(parameters)
                .WithPrivateKey(stuck.GetEncoded()).Build();

            InvalidOperationException e = Assert.Throws<InvalidOperationException>(
                () => XmssEngine.GenerateMTSignature(stuck, new byte[]{ 0x11 }),
                "a spent layer zero state at leaf 0 must not sign again");
            Assert.AreEqual("one time key at index " + boundary + " has already signed", e.Message);

            e = Assert.Throws<InvalidOperationException>(
                () => XmssEngine.GenerateMTSignature(restored, new byte[]{ 0x12 }),
                "nor once read back from its encoding");
            Assert.AreEqual("one time key at index " + boundary + " has already signed", e.Message);
        }

        /// <summary>
        /// The other side of <see cref="TestMTSigningIsRefusedOnASpentLayerZeroStateAtLeafZero"/>: a key standing
        /// on the first leaf of a subtree, holding the marked state carried over from the last leaf of the one
        /// before, signs straight through the boundary.
        /// </summary>
        [Test]
        public void TestMTSigningRollsOverALayerBoundary()
        {
            XmssMTParameters parameters = new XmssMTParameters(Height, Layers, new Sha256Digest());
            XmssMTKeyPairGenerator kpg = new XmssMTKeyPairGenerator();

            kpg.Init(new XmssMTKeyGenerationParameters(new SecureRandom(), parameters));

            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();
            XmssMTPrivateKeyParameters key = (XmssMTPrivateKeyParameters)kp.Private;
            XmssMTPublicKeyParameters publicKey = (XmssMTPublicKeyParameters)kp.Public;
            int boundary = 1 << parameters.XmssParameters.Height;

            for (int i = 0; i != boundary; i++)
            {
                XmssEngine.GenerateMTSignature(key, new byte[]{ (byte)i });
            }

            Assert.AreEqual(boundary, key.Index);
            Assert.AreEqual(boundary - 1, key.GetBdsState().Get(0).Index, "the carried state at the last leaf");
            Assert.IsTrue(key.GetBdsState().Get(0).IsUsed, "is marked");

            for (int i = boundary; i != boundary + 2; i++)
            {
                byte[] message = new byte[]{ (byte)i };
                byte[] signature = XmssEngine.GenerateMTSignature(key, message);

                Assert.IsTrue(XmssEngine.VerifyMTSignature(publicKey, message, signature), "signature " + i);
            }
            Assert.AreEqual(boundary + 2, key.Index);
        }

        /// <summary>
        /// Rolling the key replaces its state map, but signing still installs subtree states into the map as it
        /// descends the layers, so the builder copies a map it is handed rather than adopting it: adopting it would
        /// leave two keys reading authentication paths out of one map while each sits at its own index.
        /// </summary>
        [Test]
        public void TestKeyBuilderCopiesTheTraversalStateItIsGiven()
        {
            XmssMTParameters parameters = new XmssMTParameters(Height, Layers, new Sha256Digest());
            XmssMTPrivateKeyParameters key = MTKey(parameters);

            // sign once so layer zero is populated and its position is something to watch
            XmssEngine.GenerateMTSignature(key, new byte[]{ 0x01 });
            Assert.AreEqual(1L, key.Index);

            XmssMTPrivateKeyParameters shard = new XmssMTPrivateKeyParameters.Builder(parameters)
                .WithSecretKeySeed(key.GetSecretKeySeed()).WithSecretKeyPrf(key.GetSecretKeyPrf())
                .WithPublicSeed(key.GetPublicSeed()).WithRoot(key.GetRoot())
                .WithIndex(key.Index)
                .WithBdsState(key.GetBdsState()).Build();

            Assert.AreNotSame(key.GetBdsState(), shard.GetBdsState(),
                "the builder must copy the state map it is given, not adopt it");

            int before = shard.GetBdsState().Get(0).Index;

            XmssEngine.GenerateMTSignature(key, new byte[]{ 0x02 });

            Assert.AreEqual(2L, key.Index, "the other key's index moved");
            Assert.AreEqual(1L, shard.Index, "the shard's index did not");
            Assert.AreEqual(before, shard.GetBdsState().Get(0).Index,
                "nor may its traversal state, or it would sign again under the key at index 1");
        }

        /// <summary>
        /// <see cref="XmssEngine.GetNextBdsStateMap"/> hands the advanced state back rather than applying it to the
        /// map it was given, so a caller holding a map taken off a live key gets a map of its own, and the key is
        /// untouched.
        /// </summary>
        [Test]
        public void TestTakingTheNextStateOffAKeyLeavesTheKeyWhereItWas()
        {
            XmssMTParameters parameters = new XmssMTParameters(Height, Layers, new Sha256Digest());
            XmssMTPrivateKeyParameters key = MTKey(parameters);

            XmssEngine.GenerateMTSignature(key, new byte[]{ 0x01 });

            BdsStateMap held = key.GetBdsState();
            int before = held.Get(0).Index;

            BdsStateMap next = XmssEngine.GetNextBdsStateMap(held, key.Parameters, key.Index, key.GetPublicSeed(),
                key.GetSecretKeySeed());

            Assert.AreNotSame(held, next, "the advanced state has to be a new map");
            Assert.AreEqual(before + 1, next.Get(0).Index, "and it is the one that moved");

            Assert.AreSame(held, key.GetBdsState(), "the key still holds the state it had");
            Assert.AreEqual(before, held.Get(0).Index, "which has not moved");
            Assert.AreEqual(1L, key.Index, "nor has its index");
        }

        /// <summary>
        /// So a caller cannot part a key's index from its traversal state: taking the next state off the map a
        /// holder got from the key changes nothing about the key, which signs on at the index it was on.
        /// </summary>
        [Test]
        public void TestAHolderCannotMoveAKeysStateOutFromUnderIt()
        {
            XmssMTParameters parameters = new XmssMTParameters(Height, Layers, new Sha256Digest());
            XmssMTKeyPairGenerator kpg = new XmssMTKeyPairGenerator();

            kpg.Init(new XmssMTKeyGenerationParameters(new SecureRandom(), parameters));

            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();
            XmssMTPrivateKeyParameters key = (XmssMTPrivateKeyParameters)kp.Private;
            XmssMTPublicKeyParameters publicKey = (XmssMTPublicKeyParameters)kp.Public;

            XmssEngine.GenerateMTSignature(key, new byte[]{ 0x01 });

            XmssEngine.GetNextBdsStateMap(key.GetBdsState(), key.Parameters, key.Index, key.GetPublicSeed(),
                key.GetSecretKeySeed());

            byte[] message = new byte[]{ 0x02 };
            byte[] signature = XmssEngine.GenerateMTSignature(key, message);

            Assert.AreEqual(2L, key.Index, "the key spent one index, the one it was on");
            Assert.IsTrue(XmssEngine.VerifyMTSignature(publicKey, message, signature),
                "the signature taken after a holder advanced the state it was handed");

            // and on, through the subtree boundary that advance would have skipped
            for (int i = 2; i != (1 << Height); i++)
            {
                message = new byte[]{ (byte)i };

                Assert.IsTrue(XmssEngine.VerifyMTSignature(publicKey, message,
                    XmssEngine.GenerateMTSignature(key, message)), "signature at index " + i);
            }
        }

        private static XmssMTPrivateKeyParameters MTKey(XmssMTParameters parameters)
        {
            XmssMTKeyPairGenerator kpg = new XmssMTKeyPairGenerator();

            kpg.Init(new XmssMTKeyGenerationParameters(new SecureRandom(), parameters));

            return (XmssMTPrivateKeyParameters)kpg.GenerateKeyPair().Private;
        }
    }
}
