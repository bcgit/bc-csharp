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
    /// A signer's private key field is not the lock to take, because the signer itself replaces it:
    /// <see cref="XmssSigner.GetUpdatedPrivateKey"/> installs the shard the signer keeps and
    /// <see cref="XmssSigner.Init"/> installs a new key outright. A call that read the old key and a call that read
    /// the new one would hold two different locks and exclude each other from nothing.
    /// </summary>
    /// <remarks>
    /// <para>
    /// What comes out of that is the failure a stateful scheme cannot have: the key handed to the caller to persist
    /// sits on the index a signature that had already read the same object then spends, so storing and restoring it
    /// signs a second message under one WOTS+ one-time key (RFC 8391 sec. 1.1). The invariant asserted is a range
    /// one, not a timing one: whatever order the two calls take, the key handed back for storage sits strictly past
    /// every index the signer has spent.
    /// </para>
    /// <para>
    /// The XMSS method; the XMSS^MT methods arrive with the XMSS^MT signer.
    /// <see cref="SameKeyTwoSigners_DistinctIndexes"/> covers two signers holding one key, which the Java fixture
    /// does not assert directly.
    /// </para>
    /// </remarks>
    [TestFixture]
    public class SignerConcurrencyTests
    {
        private const int Height = 4;
        private const int Trials = 120;

        [Test]
        [Explicit] // slow: ~60s
        public void TestStoredXmssKeyNeverSitsOnASignedIndex()
        {
            CheckStoredXmssKeyNeverSitsOnASignedIndex(Trials, true);
        }

        /// <summary>
        /// <see cref="TestStoredXmssKeyNeverSitsOnASignedIndex"/> in the default run: one key pair is generated, and
        /// each trial races on a fresh copy of its private key decoded from one encoding, which costs no tree walk.
        /// </summary>
        [Test]
        public void StoredXmssKeyNeverSitsOnASignedIndex_FewTrials()
        {
            CheckStoredXmssKeyNeverSitsOnASignedIndex(24, false);
        }

        private static void CheckStoredXmssKeyNeverSitsOnASignedIndex(int trials, bool freshKeys)
        {
            XmssParameters parameters = new XmssParameters(Height, new Sha256Digest());
            SecureRandom random = new SecureRandom();
            int checkedTrials = 0;
            byte[] encoded = null;

            for (int trial = 0; trial != trials; trial++)
            {
                XmssPrivateKeyParameters privateKey;
                if (freshKeys || encoded == null)
                {
                    XmssKeyPairGenerator kpg = new XmssKeyPairGenerator();

                    kpg.Init(new XmssKeyGenerationParameters(random, parameters));

                    privateKey = (XmssPrivateKeyParameters)kpg.GenerateKeyPair().Private;
                    encoded = privateKey.GetEncoded();
                }
                else
                {
                    privateKey = new XmssPrivateKeyParameters.Builder(parameters).WithPrivateKey(encoded).Build();
                }

                XmssSigner signer = new XmssSigner();

                signer.Init(true, privateKey);
                signer.BlockUpdate(new byte[]{ 1, 2, 3 }, 0, 3);

                long signed = -1L;
                long stored = -1L;
                ManualResetEventSlim go = new ManualResetEventSlim(false);

                Thread signing = new Thread(() =>
                {
                    try
                    {
                        go.Wait();
                        // a signature and a key encoding both open with the index, 4 bytes big-endian for XMSS
                        // (RFC 8391 sec. 4.1.8)
                        signed = XmssHarnessTests.IndexOf(signer.GenerateSignature());
                    }
                    catch (Exception)
                    {
                        // a key already handed over is a legitimate outcome of the other ordering
                    }
                });

                Thread collecting = new Thread(() =>
                {
                    try
                    {
                        go.Wait();

                        XmssPrivateKeyParameters key = (XmssPrivateKeyParameters)signer.GetUpdatedPrivateKey();

                        if (key != null)
                        {
                            // as a caller persisting it does. The encode takes the key's own lock, so it lands either
                            // side of a signature but never inside one
                            stored = XmssHarnessTests.IndexOf(key.GetEncoded());
                        }
                    }
                    catch (Exception)
                    {
                    }
                });

                signing.Start();
                collecting.Start();
                go.Set();
                signing.Join();
                collecting.Join();

                if (signed >= 0 && stored >= 0)
                {
                    Assert.IsTrue(stored > signed, "XMSS key stored at index " + stored + " after index " + signed
                        + " was signed");
                    checkedTrials++;
                }
            }

            // the ordering where both calls succeed is the one the range check is about; a run that never reached
            // it checked nothing
            Assert.IsTrue(checkedTrials > 0, "no trial both signed and stored a key");
        }

        /// <summary>
        /// Two signers initialised with the same private key object, signing alternately and then concurrently,
        /// never emit two signatures at one index, and every signature verifies.
        /// </summary>
        [Test]
        public void SameKeyTwoSigners_DistinctIndexes()
        {
            XmssParameters parameters = new XmssParameters(Height, new Sha256Digest());
            XmssKeyPairGenerator kpg = new XmssKeyPairGenerator();

            kpg.Init(new XmssKeyGenerationParameters(new SecureRandom(), parameters));

            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();
            XmssPrivateKeyParameters privKey = (XmssPrivateKeyParameters)kp.Private;
            XmssSigner[] signers = new XmssSigner[]{ new XmssSigner(), new XmssSigner() };

            signers[0].Init(true, privKey);
            signers[1].Init(true, privKey);

            List<KeyValuePair<byte[], byte[]>> sigs = new List<KeyValuePair<byte[], byte[]>>();

            // alternating, eight signatures
            for (int i = 0; i != 8; i++)
            {
                byte[] message = new byte[]{ (byte)i };
                sigs.Add(new KeyValuePair<byte[], byte[]>(message, XmssHarnessTests.Sign(signers[i % 2], message)));
            }

            // and concurrently, the remaining eight. A thread's exception is kept and reported after the join: left
            // unhandled it would take the test host down rather than fail the test
            Thread[] threads = new Thread[2];
            Exception[] failures = new Exception[2];
            for (int t = 0; t != 2; t++)
            {
                XmssSigner signer = signers[t];
                byte tag = (byte)(0x80 + t);
                int slot = t;
                threads[t] = new Thread(() =>
                {
                    try
                    {
                        for (int i = 0; i != 4; i++)
                        {
                            byte[] message = new byte[]{ tag, (byte)i };
                            byte[] sig = XmssHarnessTests.Sign(signer, message);
                            lock (sigs)
                            {
                                sigs.Add(new KeyValuePair<byte[], byte[]>(message, sig));
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        failures[slot] = e;
                    }
                });
            }
            foreach (Thread thread in threads)
            {
                thread.Start();
            }
            foreach (Thread thread in threads)
            {
                thread.Join();
            }
            for (int t = 0; t != 2; t++)
            {
                Assert.IsNull(failures[t], "signing thread " + t + " failed: " + failures[t]);
            }

            Assert.AreEqual(1 << Height, sigs.Count);
            Assert.AreEqual(0, privKey.GetUsagesRemaining());

            XmssSigner verifier = new XmssSigner();
            verifier.Init(false, kp.Public);
            HashSet<int> seen = new HashSet<int>();
            foreach (KeyValuePair<byte[], byte[]> pair in sigs)
            {
                int index = XmssHarnessTests.IndexOf(pair.Value);
                Assert.IsTrue(seen.Add(index), "one-time key at index " + index + " signed twice");
                Assert.IsTrue(XmssHarnessTests.Verify(verifier, pair.Key, pair.Value), "index " + index);
            }

            // and the key they share is spent for both
            Assert.Throws<ExhaustedPrivateKeyException>(() => XmssHarnessTests.Sign(signers[0], new byte[1]));
            Assert.Throws<ExhaustedPrivateKeyException>(() => XmssHarnessTests.Sign(signers[1], new byte[1]));
        }
    }
}
