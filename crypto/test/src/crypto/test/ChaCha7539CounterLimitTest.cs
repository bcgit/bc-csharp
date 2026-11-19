using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Tests
{
    /// <summary>
    /// <see cref="ChaCha7539Engine"/> at the end of its 32-bit block counter: RFC 8439 allows counter 0xFFFFFFFF, and
    /// no block may follow it.
    /// </summary>
    /// <remarks>
    /// Reaching the end of the counter from 0 takes 2^32 blocks (256 GiB), so the tests start the counter near the end
    /// through the internal engine state.
    /// </remarks>
    [TestFixture]
    public class ChaCha7539CounterLimitTest
    {
        // Wycheproof chacha20_counter_test.json (C2SP/wycheproof), ChaCha20-IETF group: all-zero key and nonce, so the
        // ciphertext of an all-zero message is the keystream. tcId 35 starts at counter 0xFFFFFFFE (128 bytes); tcId
        // 39 at 0xFFFFFFFF (64 bytes) is its second half. tcIds 40-42 (0xFFFFFFFF, 65+ bytes) must be refused.
        private const string KeystreamFFFFFFFE =
              "032cc123482c31711f94c941af5ab1f4155784332ed5348fe79aec5ead4c06c3"
            + "f13c280d8cc49925e4a6a5922ec80e13a4cdfa840c70a1427a3cb699166991a5";
        private const string KeystreamFFFFFFFF =
              "ace4cd09e294d1912d4ad205d06f95d9c2f2bfcf453e8753f128765b62215f4d"
            + "92c74f2f626c6a640c0b1284d839ec81f1696281dafc3e684593937023b58b1d";

        private static ChaCha7539Engine CreateEngine(uint initialCounter)
        {
            var engine = new ChaCha7539Engine();
            engine.Init(true, new ParametersWithIV(new KeyParameter(new byte[32]), new byte[12]));
            engine.engineState[12] = initialCounter;
            return engine;
        }

        private static byte[] ProcessBytes(ChaCha7539Engine engine, int length)
        {
            byte[] output = new byte[length];
            engine.ProcessBytes(new byte[length], 0, length, output, 0);
            return output;
        }

        [Test]
        public void LastCounterBlockIsUsable()
        {
            Assert.AreEqual(KeystreamFFFFFFFF, Hex.ToHexString(ProcessBytes(CreateEngine(0xFFFFFFFFU), 64)));
        }

        [Test]
        public void LastTwoCounterBlocksAreUsable()
        {
            Assert.AreEqual(KeystreamFFFFFFFE + KeystreamFFFFFFFF,
                Hex.ToHexString(ProcessBytes(CreateEngine(0xFFFFFFFEU), 128)));
        }

        [Test]
        public void LastCounterBlockIsUsableByteByByte()
        {
            var engine = CreateEngine(0xFFFFFFFFU);
            byte[] output = new byte[64];
            for (int i = 0; i < output.Length; ++i)
            {
                output[i] = engine.ReturnByte(0);
            }
            Assert.AreEqual(KeystreamFFFFFFFF, Hex.ToHexString(output));

            Assert.Throws<InvalidOperationException>(() => engine.ReturnByte(0));
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        [Test]
        public void LastCounterBlockIsUsableSpan()
        {
            var engine = CreateEngine(0xFFFFFFFEU);
            byte[] output = new byte[128];
            engine.ProcessBytes(new byte[128], output);
            Assert.AreEqual(KeystreamFFFFFFFE + KeystreamFFFFFFFF, Hex.ToHexString(output));
        }
#endif

        [Test]
        public void BlockPastTheLastIsRefused()
        {
            var engine = CreateEngine(0xFFFFFFFFU);
            Assert.Throws<InvalidOperationException>(() => ProcessBytes(engine, 65));
        }

        [Test]
        public void BlockPastTheLastIsRefusedInLaterCalls()
        {
            var engine = CreateEngine(0xFFFFFFFFU);
            Assert.AreEqual(KeystreamFFFFFFFF, Hex.ToHexString(ProcessBytes(engine, 64)));

            // The counter has wrapped to 0: a further block would repeat the keystream of counter 0.
            Assert.Throws<InvalidOperationException>(() => ProcessBytes(engine, 1));
            Assert.Throws<InvalidOperationException>(() => ProcessBytes(engine, 1));
        }

        [Test]
        public void ResetClearsTheExhaustedCounter()
        {
            var engine = CreateEngine(0xFFFFFFFFU);
            ProcessBytes(engine, 64);
            Assert.Throws<InvalidOperationException>(() => ProcessBytes(engine, 1));

            engine.Reset();

            var fresh = new ChaCha7539Engine();
            fresh.Init(true, new ParametersWithIV(new KeyParameter(new byte[32]), new byte[12]));
            Assert.IsTrue(Arrays.AreEqual(ProcessBytes(fresh, 64), ProcessBytes(engine, 64)));
        }

        [Test]
        public void ProcessBlocksAllowsTheLastCounterBlock()
        {
            var engine = CreateEngine(0xFFFFFFFEU);
            byte[] output = new byte[128];
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            int processed = engine.ProcessBlocks(new byte[128], output);
#else
            int processed = engine.ProcessBlocks(new byte[128], 0, 128, output, 0);
#endif
            Assert.AreEqual(128, processed);
            Assert.AreEqual(KeystreamFFFFFFFE + KeystreamFFFFFFFF, Hex.ToHexString(output));

            // Whichever path processed the blocks (scalar or SIMD), the counter is now exhausted.
            Assert.Throws<InvalidOperationException>(() => ProcessBytes(engine, 1));
        }

        [Test]
        public void ProcessBlocksRefusesBlocksPastTheLast()
        {
            var engine = CreateEngine(0xFFFFFFFFU);
            byte[] output = new byte[128];
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Assert.Throws<MaxBytesExceededException>(() => engine.ProcessBlocks(new byte[128], output));
#else
            Assert.Throws<MaxBytesExceededException>(() => engine.ProcessBlocks(new byte[128], 0, 128, output, 0));
#endif
        }
    }
}
