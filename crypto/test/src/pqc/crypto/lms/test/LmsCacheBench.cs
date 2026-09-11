using System;
using System.Diagnostics;
using System.Threading;

using NUnit.Framework;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Lms.Tests
{
    /// <summary>
    /// <c>[Explicit]</c> timings for the LMS private key's tree cache: key generation, the first signature, a run
    /// of consecutive signatures (mean and worst), the first signature after decoding, the first signature of a
    /// shard, and interleaved signers over one key. Single runs, no attempt to average out noise.
    /// </summary>
    [TestFixture]
    public class LmsCacheBench
    {
        private const int Sequential = 64, Threads = 4, PerThread = 32;

        [Test, Explicit]
        [TestCase(10)]
        [TestCase(15)]
        public void Bench(int h)
        {
            LMSigParameters sigParams = h == 10
                ? LMSigParameters.lms_sha256_n32_h10
                : LMSigParameters.lms_sha256_n32_h15;
            LMOtsParameters otsParams = LMOtsParameters.sha256_n32_w8;
            byte[] msg = Strings.ToByteArray("tree cache benchmark");

            SecureRandom random = new SecureRandom();
            byte[] I = SecureRandom.GetNextBytes(random, 16);
            byte[] seed = SecureRandom.GetNextBytes(random, 32);

            var sw = Stopwatch.StartNew();
            LmsPrivateKeyParameters key = Lms.GenerateKeys(sigParams, otsParams, 0, I, seed);
            LmsPublicKeyParameters pub = key.GetPublicKey();
            sw.Stop();
            TestContext.WriteLine($"h={h} keygen (with public key): {sw.Elapsed.TotalMilliseconds:N1} ms");

            LmsSigner signer = new LmsSigner();
            signer.Init(true, key);

            sw.Restart();
            byte[] sig = signer.GenerateSignature(msg);
            sw.Stop();
            TestContext.WriteLine($"h={h} first signature: {sw.Elapsed.TotalMilliseconds:N2} ms");

            double total = 0.0, worst = 0.0;
            int worstQ = -1;
            for (int i = 1; i < Sequential; ++i)
            {
                sw.Restart();
                sig = signer.GenerateSignature(msg);
                sw.Stop();

                double ms = sw.Elapsed.TotalMilliseconds;
                total += ms;
                if (ms > worst)
                {
                    worst = ms;
                    worstQ = i;
                }
            }
            TestContext.WriteLine($"h={h} sequential q=1..{Sequential - 1}: mean {total / (Sequential - 1):N2} ms," +
                $" worst {worst:N2} ms at q={worstQ}");

            Assert.True(Verify(pub, sig, msg));

            byte[] enc = key.GetEncoded();
            LmsPrivateKeyParameters decoded = LmsPrivateKeyParameters.GetInstance(enc);
            LmsSigner decodedSigner = new LmsSigner();
            decodedSigner.Init(true, decoded);
            sw.Restart();
            sig = decodedSigner.GenerateSignature(msg);
            sw.Stop();
            TestContext.WriteLine(
                $"h={h} first signature after decode (q={Sequential}): {sw.Elapsed.TotalMilliseconds:N2} ms");
            Assert.True(Verify(pub, sig, msg));

            LmsPrivateKeyParameters shard = key.ExtractKeyShard(8);
            LmsSigner shardSigner = new LmsSigner();
            shardSigner.Init(true, shard);
            sw.Restart();
            sig = shardSigner.GenerateSignature(msg);
            sw.Stop();
            TestContext.WriteLine(
                $"h={h} first signature of a shard (q={Sequential}): {sw.Elapsed.TotalMilliseconds:N2} ms");
            Assert.True(Verify(pub, sig, msg));

            Thread[] threads = new Thread[Threads];
            for (int t = 0; t < Threads; ++t)
            {
                threads[t] = new Thread(() =>
                {
                    LmsSigner s = new LmsSigner();
                    s.Init(true, key);
                    for (int i = 0; i < PerThread; ++i)
                    {
                        s.GenerateSignature(msg);
                    }
                });
            }

            sw.Restart();
            foreach (Thread thread in threads)
            {
                thread.Start();
            }
            foreach (Thread thread in threads)
            {
                thread.Join();
            }
            sw.Stop();
            TestContext.WriteLine($"h={h} {Threads} threads x {PerThread} signatures:" +
                $" {sw.Elapsed.TotalMilliseconds:N1} ms ({sw.Elapsed.TotalMilliseconds / (Threads * PerThread):N2} ms" +
                " per signature)");
        }

        private static bool Verify(LmsPublicKeyParameters key, byte[] signature, byte[] message)
        {
            LmsSigner signer = new LmsSigner();
            signer.Init(false, key);
            return signer.VerifySignature(message, signature);
        }
    }
}
