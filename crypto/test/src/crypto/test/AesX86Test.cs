// NOTE: .NET Core 3.1 is tested against our .NET Standard 2.0 assembly.
//#if NETCOREAPP3_0_OR_GREATER
#if NET6_0_OR_GREATER
using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    [TestFixture, TestOf(typeof(AesEngine_X86))]
    public class AesX86Test
        : CipherTest
    {
        private static SimpleTest[] CreateBlockCipherVectors() => new SimpleTest[]
        {
            CreateVectorTest(0, "80000000000000000000000000000000", "00000000000000000000000000000000", "0EDD33D3C621E546455BD8BA1418BEC8"),
            CreateVectorTest(1, "00000000000000000000000000000080", "00000000000000000000000000000000", "172AEAB3D507678ECAF455C12587ADB7"),
            CreateMonteCarloTest(2, 10000, "00000000000000000000000000000000", "00000000000000000000000000000000", "C34C052CC0DA8D73451AFE5F03BE297F"),
            CreateMonteCarloTest(3, 10000, "5F060D3716B345C253F6749ABAC10917", "355F697E8B868B65B25A04E18D782AFA", "ACC863637868E3E068D2FD6E3508454A"),
            CreateVectorTest(4, "000000000000000000000000000000000000000000000000", "80000000000000000000000000000000", "6CD02513E8D4DC986B4AFE087A60BD0C"),
            CreateMonteCarloTest(5, 10000, "AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114", "F3F6752AE8D7831138F041560631B114", "77BA00ED5412DFF27C8ED91F3C376172"),
            CreateVectorTest(6, "0000000000000000000000000000000000000000000000000000000000000000", "80000000000000000000000000000000", "DDC6BF790C15760D8D9AEB6F9A75FD4E"),
            CreateMonteCarloTest(7, 10000, "28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386", "C737317FE0846F132B23C8C2A672CE22", "E58B82BFBA53C0040DC610C642121168"),
            CreateVectorTest(8, "80000000000000000000000000000000", "00000000000000000000000000000000", "0EDD33D3C621E546455BD8BA1418BEC8"),
            CreateVectorTest(9, "00000000000000000000000000000080", "00000000000000000000000000000000", "172AEAB3D507678ECAF455C12587ADB7"),
            CreateMonteCarloTest(10, 10000, "00000000000000000000000000000000", "00000000000000000000000000000000", "C34C052CC0DA8D73451AFE5F03BE297F"),
            CreateMonteCarloTest(11, 10000, "5F060D3716B345C253F6749ABAC10917", "355F697E8B868B65B25A04E18D782AFA", "ACC863637868E3E068D2FD6E3508454A"),
            CreateVectorTest(12, "000000000000000000000000000000000000000000000000", "80000000000000000000000000000000", "6CD02513E8D4DC986B4AFE087A60BD0C"),
            CreateMonteCarloTest(13, 10000, "AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114", "F3F6752AE8D7831138F041560631B114", "77BA00ED5412DFF27C8ED91F3C376172"),
            CreateVectorTest(14, "0000000000000000000000000000000000000000000000000000000000000000", "80000000000000000000000000000000", "DDC6BF790C15760D8D9AEB6F9A75FD4E"),
            CreateMonteCarloTest(15, 10000, "28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386", "C737317FE0846F132B23C8C2A672CE22", "E58B82BFBA53C0040DC610C642121168"),
            CreateVectorTest(16, "80000000000000000000000000000000", "00000000000000000000000000000000", "0EDD33D3C621E546455BD8BA1418BEC8"),
            CreateVectorTest(17, "00000000000000000000000000000080", "00000000000000000000000000000000", "172AEAB3D507678ECAF455C12587ADB7"),
            CreateMonteCarloTest(18, 10000, "00000000000000000000000000000000", "00000000000000000000000000000000", "C34C052CC0DA8D73451AFE5F03BE297F"),
            CreateMonteCarloTest(19, 10000, "5F060D3716B345C253F6749ABAC10917", "355F697E8B868B65B25A04E18D782AFA", "ACC863637868E3E068D2FD6E3508454A"),
            CreateVectorTest(20, "000000000000000000000000000000000000000000000000", "80000000000000000000000000000000", "6CD02513E8D4DC986B4AFE087A60BD0C"),
            CreateMonteCarloTest(21, 10000, "AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114", "F3F6752AE8D7831138F041560631B114", "77BA00ED5412DFF27C8ED91F3C376172"),
            CreateVectorTest(22, "0000000000000000000000000000000000000000000000000000000000000000", "80000000000000000000000000000000", "DDC6BF790C15760D8D9AEB6F9A75FD4E"),
            CreateMonteCarloTest(23, 10000, "28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386", "C737317FE0846F132B23C8C2A672CE22", "E58B82BFBA53C0040DC610C642121168")
        };

        private static SimpleTest CreateMonteCarloTest(int id, int iters, string key, string input, string output) =>
            new BlockCipherMonteCarloTest(id, iters, new AesEngine_X86(), HexKey(key), input, output);

        private static SimpleTest CreateVectorTest(int id, string key, string input, string output) =>
            new BlockCipherVectorTest(id, new AesEngine_X86(), HexKey(key), input, output);

        private static KeyParameter HexKey(string key) => new KeyParameter(Hex.DecodeStrict(key));

        private readonly SecureRandom Random = new SecureRandom();

        [OneTimeSetUp]
        public void OneTimeSetUp()
        {
            if (!AesEngine_X86.IsSupported)
            {
                Assert.Ignore();
            }
        }

        public override string Name => "AesX86";

        [Test, Explicit]
        public void BenchDecrypt128() => ImplBenchProcess(forEncryption: false, keySize: 128);

        [Test, Explicit]
        public void BenchDecrypt192() => ImplBenchProcess(forEncryption: false, keySize: 192);

        [Test, Explicit]
        public void BenchDecrypt256() => ImplBenchProcess(forEncryption: false, keySize: 256);

        [Test, Explicit]
        public void BenchDecryptFour128() => ImplBenchProcessFour(forEncryption: false, keySize: 128);

        [Test, Explicit]
        public void BenchDecryptFour192() => ImplBenchProcessFour(forEncryption: false, keySize: 192);

        [Test, Explicit]
        public void BenchDecryptFour256() => ImplBenchProcessFour(forEncryption: false, keySize: 256);

        [Test, Explicit]
        public void BenchEncrypt128() => ImplBenchProcess(forEncryption: true, keySize: 128);

        [Test, Explicit]
        public void BenchEncrypt192() => ImplBenchProcess(forEncryption: true, keySize: 192);

        [Test, Explicit]
        public void BenchEncrypt256() => ImplBenchProcess(forEncryption: true, keySize: 256);

        [Test, Explicit]
        public void BenchEncryptFour128() => ImplBenchProcessFour(forEncryption: true, keySize: 128);

        [Test, Explicit]
        public void BenchEncryptFour192() => ImplBenchProcessFour(forEncryption: true, keySize: 192);

        [Test, Explicit]
        public void BenchEncryptFour256() => ImplBenchProcessFour(forEncryption: true, keySize: 256);

        [Test]
        public void BlockCipherVectors() => RunTests(CreateBlockCipherVectors());

        [Test]
        public void EngineChecks128() => ImplEngineChecks(keySize: 128);

        [Test]
        public void EngineChecks192() => ImplEngineChecks(keySize: 192);

        [Test]
        public void EngineChecks256() => ImplEngineChecks(keySize: 256);

        [Test]
        public void FourBlocksDecrypt128() => ImplTestFourBlocks(forEncryption: false, keySize: 128);

        [Test]
        public void FourBlocksDecrypt192() => ImplTestFourBlocks(forEncryption: false, keySize: 192);

        [Test]
        public void FourBlocksDecrypt256() => ImplTestFourBlocks(forEncryption: false, keySize: 256);

        [Test]
        public void FourBlocksEncrypt128() => ImplTestFourBlocks(forEncryption: true, keySize: 128);

        [Test]
        public void FourBlocksEncrypt192() => ImplTestFourBlocks(forEncryption: true, keySize: 192);

        [Test]
        public void FourBlocksEncrypt256() => ImplTestFourBlocks(forEncryption: true, keySize: 256);

        private void ImplBenchProcess(bool forEncryption, int keySize)
        {
            var engine = RandomEngine(forEncryption, keySize);
            Span<byte> data = stackalloc byte[16];
            Random.NextBytes(data);
            for (int i = 0; i < 1000000000; ++i)
            {
                engine.ProcessBlock(data, data);
            }
        }

        private void ImplBenchProcessFour(bool forEncryption, int keySize)
        {
            var engine = RandomEngine(forEncryption, keySize);
            Span<byte> data = stackalloc byte[64];
            Random.NextBytes(data);
            for (int i = 0; i < 1000000000 / 4; ++i)
            {
                engine.ProcessFourBlocks(data, data);
            }
        }

        private void ImplEngineChecks(int keySize) => RunEngineChecks(new AesEngine_X86(), RandomKey(keySize));

        private void ImplTestFourBlocks(bool forEncryption, int keySize)
        {
            Span<byte> data = stackalloc byte[64];
            Span<byte> fourBlockOutput = stackalloc byte[64];
            Span<byte> singleBlockOutput = stackalloc byte[64];

            for (int i = 0; i < 100; ++i)
            {
                Random.NextBytes(data);

                var engine = RandomEngine(forEncryption, keySize);

                engine.ProcessFourBlocks(data, fourBlockOutput);

                for (int j = 0; j < 64; j += 16)
                {
                    engine.ProcessBlock(data[j..], singleBlockOutput[j..]);
                }

                Assert.IsTrue(fourBlockOutput.SequenceEqual(singleBlockOutput));
            }
        }

        private AesEngine_X86 RandomEngine(bool forEncryption, int keySize)
        {
            var engine = new AesEngine_X86();
            engine.Init(forEncryption, RandomKey(keySize));
            return engine;
        }

        private KeyParameter RandomKey(int keySize) => KeyParameter.Create(keySize / 8, Random, SecureRandom.Fill);
    }
}
#endif
