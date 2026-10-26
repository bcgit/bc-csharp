using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Tests
{
    [TestFixture]
    public class Argon2Test
    {
        private const int DefaultOutputLen = 32;

        #region "Exception tests"
        [Test]
        public void TestExceptions()
        {
            // Parallelism less than MIN_PARALLELISM
            CheckInvalidConfig(b => b.WithParallelism(0));

            // Parallelism greater than MAX_PARALLELISM
            CheckInvalidConfig(b => b.WithParallelism(1 << 24));

            // iterations less than MIN_ITERATIONS
            CheckInvalidConfig(b => b.WithIterations(0));

            // output length less than MIN_OUTLEN
            Assert.Throws<InvalidOperationException>(() =>
            {
                Argon2BytesGenerator gen = new Argon2BytesGenerator();
                Argon2Parameters parameters = new Argon2Parameters.Builder().Build();
                gen.Init(parameters);
                byte[] result = new byte[3];
                gen.GenerateBytes("password".ToCharArray(), result);
            });
        }
        #endregion

        #region "Permutation based tests"
        [Test]
        public void TestPermutations()
        {
            byte[] rootPassword = Encoding.ASCII.GetBytes("aac");
            byte[] buf;

            byte[][] salts = new byte[][] {
                new byte[16],
                new byte[16],
                new byte[16]
            };

            for (int t = 0; t < 16; t++)
            {
                salts[1][t] = (byte)t;
                salts[2][t] = (byte)(16 - t);
            }

            //
            // Permutation, starting with a shorter array, same length then one longer.
            //
            for (int j = rootPassword.Length - 1; j < rootPassword.Length + 2; j++)
            {
                buf = new byte[j];

                for (int a = 0; a < rootPassword.Length; a++)
                {
                    for (int b = 0; b < buf.Length; b++)
                    {
                        buf[b] = rootPassword[(a + b) % rootPassword.Length];
                    }

                    List<byte[]> permutations = new List<byte[]>();
                    Permute(permutations, buf, 0, buf.Length - 1);

                    for (int i = 0; i != permutations.Count; i++)
                    {
                        byte[] candidate = permutations[i];
                        for (int k = 0; k != salts.Length; k++)
                        {
                            byte[] salt = salts[k];
                            byte[] expected = Generate(Argon2Parameters.Version10, 1, 8, 2, rootPassword, salt, 32);
                            byte[] testValue = Generate(Argon2Parameters.Version10, 1, 8, 2, candidate, salt, 32);

                            //
                            // If the passwords are the same for the same salt we should have the same string.
                            //
                            bool sameAsRoot = Arrays.AreEqual(rootPassword, candidate);
                            Assert.AreEqual(sameAsRoot, Arrays.AreEqual(expected, testValue), "expected same result");
                        }
                    }
                }
            }
        }

        private static void CheckInvalidConfig(Action<Argon2Parameters.Builder> config)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() =>
            {
                var generator = new Argon2BytesGenerator();
                var builder = new Argon2Parameters.Builder();
                config(builder);
                var parameters = builder.Build();
                generator.Init(parameters);
            });
        }

        private static void Swap(byte[] buf, int i, int j)
        {
            byte b = buf[i];
            buf[i] = buf[j];
            buf[j] = b;
        }

        private static void Permute(List<byte[]> permutation, byte[] a, int l, int r)
        {
            if (l == r)
            {
                permutation.Add(Arrays.Clone(a));
            }
            else
            {

                for (int i = l; i <= r; i++)
                {
                    // Swapping done
                    Swap(a, l, i);

                    // Recursion called
                    Permute(permutation, a, l + 1, r);

                    //backtrack
                    Swap(a, l, i);
                }
            }
        }

        private static byte[] Generate(int version, int iterations, int memory, int parallelism, byte[] password,
            byte[] salt, int outputLength)
        {
            Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.Argon2i)
                .WithVersion(version)
                .WithIterations(iterations)
                .WithMemoryPowOfTwo(memory)
                .WithParallelism(parallelism)
                .WithSalt(salt)
                .Build();

            //
            // Set the password.
            //
            Argon2BytesGenerator gen = new Argon2BytesGenerator();
            gen.Init(parameters);

            byte[] result = new byte[outputLength];
            gen.GenerateBytes(password, result, 0, result.Length);
            return result;
        }
        #endregion

        #region "Hash tests"
        /* Multiple test cases for various input values */
        [Test]
        public void HashTestsVersion10()
        {
            /* Multiple test cases for various input values */

            int version = Argon2Parameters.Version10;

            HashTest(version, 2, 16, 1, "password", "somesalt",
                "f6c4db4a54e2a370627aff3db6176b94a2a209a62c8e36152711802f7b30c694",
                DefaultOutputLen);

            HashTest(version, 2, 20, 1, "password", "somesalt",
                "9690ec55d28d3ed32562f2e73ea62b02b018757643a2ae6e79528459de8106e9",
                DefaultOutputLen);

            HashTest(version, 2, 18, 1, "password", "somesalt",
                "3e689aaa3d28a77cf2bc72a51ac53166761751182f1ee292e3f677a7da4c2467",
                DefaultOutputLen);

            HashTest(version, 2, 8, 1, "password", "somesalt",
                "fd4dd83d762c49bdeaf57c47bdcd0c2f1babf863fdeb490df63ede9975fccf06",
                DefaultOutputLen);
            HashTest(version, 2, 8, 2, "password", "somesalt",
                "b6c11560a6a9d61eac706b79a2f97d68b4463aa3ad87e00c07e2b01e90c564fb",
                DefaultOutputLen);

            HashTest(version, 1, 16, 1, "password", "somesalt",
                "81630552b8f3b1f48cdb1992c4c678643d490b2b5eb4ff6c4b3438b5621724b2",
                DefaultOutputLen);

            HashTest(version, 4, 16, 1, "password", "somesalt",
                "f212f01615e6eb5d74734dc3ef40ade2d51d052468d8c69440a3a1f2c1c2847b",
                DefaultOutputLen);

            HashTest(version, 2, 16, 1, "differentpassword", "somesalt",
                "e9c902074b6754531a3a0be519e5baf404b30ce69b3f01ac3bf21229960109a3",
                DefaultOutputLen);

            HashTest(version, 2, 16, 1, "password", "diffsalt",
                "79a103b90fe8aef8570cb31fc8b22259778916f8336b7bdac3892569d4f1c497",
                DefaultOutputLen);

            HashTest(version, 2, 16, 1, "password", "diffsalt",
                "1a097a5d1c80e579583f6e19c7e4763ccb7c522ca85b7d58143738e12ca39f8e6e42734c950ff2463675b97c37ba" +
                    "39feba4a9cd9cc5b4c798f2aaf70eb4bd044c8d148decb569870dbd923430b82a083f284beae777812cce18cdac68ee8ccef" +
                    "c6ec9789f30a6b5a034591f51af830f4",
                112);
        }

        [Test]
        public void HashTestsVersion13()
        {
            int version = Argon2Parameters.Version13;

            HashTest(version, 2, 16, 1, "password", "somesalt",
                "c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0",
                DefaultOutputLen);

            HashTest(version, 2, 20, 1, "password", "somesalt",
                "d1587aca0922c3b5d6a83edab31bee3c4ebaef342ed6127a55d19b2351ad1f41",
                DefaultOutputLen);

            HashTest(version, 2, 18, 1, "password", "somesalt",
                "296dbae80b807cdceaad44ae741b506f14db0959267b183b118f9b24229bc7cb",
                DefaultOutputLen);

            HashTest(version, 2, 8, 1, "password", "somesalt",
                "89e9029f4637b295beb027056a7336c414fadd43f6b208645281cb214a56452f",
                DefaultOutputLen);

            HashTest(version, 2, 8, 2, "password", "somesalt",
                "4ff5ce2769a1d7f4c8a491df09d41a9fbe90e5eb02155a13e4c01e20cd4eab61",
                DefaultOutputLen);

            HashTest(version, 1, 16, 1, "password", "somesalt",
                "d168075c4d985e13ebeae560cf8b94c3b5d8a16c51916b6f4ac2da3ac11bbecf",
                DefaultOutputLen);

            HashTest(version, 4, 16, 1, "password", "somesalt",
                "aaa953d58af3706ce3df1aefd4a64a84e31d7f54175231f1285259f88174ce5b",
                DefaultOutputLen);

            HashTest(version, 2, 16, 1, "differentpassword", "somesalt",
                "14ae8da01afea8700c2358dcef7c5358d9021282bd88663a4562f59fb74d22ee",
                DefaultOutputLen);

            HashTest(version, 2, 16, 1, "password", "diffsalt",
                "b0357cccfbef91f3860b0dba447b2348cbefecadaf990abfe9cc40726c521271",
                DefaultOutputLen);
        }

        private void HashTest(int version, int iterations, int memory, int parallelism, string password, string salt,
            string passwordRef, int outputLength)
        {
            Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.Argon2i)
                .WithVersion(version)
                .WithIterations(iterations)
                .WithMemoryPowOfTwo(memory)
                .WithParallelism(parallelism)
                .WithSalt(Encoding.ASCII.GetBytes(salt))
                .Build();

            Argon2BytesGenerator gen = new Argon2BytesGenerator();
            gen.Init(parameters);

            byte[] result = new byte[outputLength];
            gen.GenerateBytes(password.ToCharArray(), result, 0, result.Length);

            Assert.True(Arrays.AreEqual(result, Hex.Decode(passwordRef)), passwordRef + " Failed");
        }
        #endregion

        #region "Known Answer Tests (KATs) from specifications"
        private void SpecsTest(int version, int type, string passwordRef)
        {
            byte[] ad = Hex.Decode("040404040404040404040404");
            byte[] secret = Hex.Decode("0303030303030303");
            byte[] salt = Hex.Decode("02020202020202020202020202020202");
            byte[] password = Hex.Decode("0101010101010101010101010101010101010101010101010101010101010101");

            byte[] expected = Hex.Decode(passwordRef);

            Argon2Parameters parameters = new Argon2Parameters.Builder(type)
                .WithVersion(version)
                .WithIterations(3)
                .WithMemoryAsKB(32)
                .WithParallelism(4)
                .WithAdditional(ad)
                .WithSecret(secret)
                .WithSalt(salt)
                .Build();

            Argon2BytesGenerator gen = new Argon2BytesGenerator();
            gen.Init(parameters);

            byte[] result = new byte[32];
            gen.GenerateBytes(password, result, 0, result.Length);

            Assert.True(Arrays.AreEqual(expected, result), passwordRef + " Failed");
        }

        [Test]
        public void TestVectorsFromSpecs()
        {
            /* Version 0x13 (19) from RFC 9106 https://datatracker.ietf.org/doc/html/rfc9106#name-test-vectors */
            SpecsTest(
                Argon2Parameters.Version13,
                Argon2Parameters.Argon2d,
                "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb");

            SpecsTest(
                Argon2Parameters.Version13,
                Argon2Parameters.Argon2i,
                "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8");

            SpecsTest(
                Argon2Parameters.Version13,
                Argon2Parameters.Argon2id,
                "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");

            /* Version 0x10 (16) from reference C implementation https://github.com/P-H-C/phc-winner-argon2/tree/master/kats */
            SpecsTest(
                Argon2Parameters.Version10,
                Argon2Parameters.Argon2d,
                "96a9d4e5a1734092c85e29f410a45914a5dd1f5cbf08b2670da68a0285abf32b");

            SpecsTest(
                Argon2Parameters.Version10,
                Argon2Parameters.Argon2i,
                "87aeedd6517ab830cd9765cd8231abb2e647a5dee08f7c05e02fcb763335d0fd");

            SpecsTest(
                Argon2Parameters.Version10,
                Argon2Parameters.Argon2id,
                "b64615f07789b66b645b67ee9ed3b377ae350b6bfcbb0fc95141ea8f322613c0");
        }
        #endregion

        [Test]
        public void CheckArgon2MaxMemoryExpValue()
        {
            Properties.WithThreadProperty(Properties.Argon2MaxMemoryExp, "10", () =>
            {
                byte[] salt = new byte[16];
                new SecureRandom().NextBytes(salt);

                try
                {
                    Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
                        .WithSalt(salt)
                        .WithIterations(1)
                        .WithParallelism(4)
                        .WithMemoryPowOfTwo(30)  // 1 << 22 = 4 GiB, no guard
                        .WithVersion(Argon2Parameters.Version13)
                        .Build();
                    Assert.Fail("no exception");
                }
                catch (ArgumentOutOfRangeException e)
                {
                    Assert.NotNull(e.Message);
                    Assert.That(e.ParamName == "memory");
                }

                try
                {
                    Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
                        .WithSalt(salt)
                        .WithIterations(1)
                        .WithParallelism(4)
                        .WithMemoryAsKB(1 << 25)
                        .WithVersion(Argon2Parameters.Version13)
                        .Build();
                    Assert.Fail("no exception");
                }
                catch (ArgumentOutOfRangeException e)
                {
                    Assert.NotNull(e.Message);
                    Assert.That(e.ParamName == "memory");
                }
            });
        }

        [Test]
        public void CheckArgon2LimitsEnforced()
        {
            // Trusted (the default): the passes and parallelism limits don't apply
            var trusted = new Argon2Parameters.Builder(Argon2Parameters.Argon2id);
            trusted.WithIterations(11).WithParallelism(17);

            var untrusted = new Argon2Parameters.Builder(Argon2Parameters.Argon2id, trusted: false);
            untrusted.WithIterations(10).WithParallelism(16);
            Assert.Throws<ArgumentOutOfRangeException>(() => untrusted.WithIterations(11));
            Assert.Throws<ArgumentOutOfRangeException>(() => untrusted.WithParallelism(17));

            Properties.WithThreadProperty(Properties.Argon2MaxPasses, "2", () =>
            Properties.WithThreadProperty(Properties.Argon2MaxParallelism, "2", () =>
            {
                new Argon2Parameters.Builder(Argon2Parameters.Argon2id).WithIterations(3).WithParallelism(3);

                var limited = new Argon2Parameters.Builder(Argon2Parameters.Argon2id, trusted: false);
                limited.WithIterations(2).WithParallelism(2);
                Assert.Throws<ArgumentOutOfRangeException>(() => limited.WithIterations(3));
                Assert.Throws<ArgumentOutOfRangeException>(() => limited.WithParallelism(3));
            }));
        }

        [Test]
        public void CheckArgon2LimitsTooSmall()
        {
            // A limit that would reject every value is a configuration error, where the limit applies
            ImplCheckArgon2LimitTooSmall(Properties.Argon2MaxMemoryExp, "2", appliesWhenTrusted: true);
            ImplCheckArgon2LimitTooSmall(Properties.Argon2MaxParallelism, "0", appliesWhenTrusted: false);
            ImplCheckArgon2LimitTooSmall(Properties.Argon2MaxPasses, "0", appliesWhenTrusted: false);
        }

        [Test]
        public void CheckArgon2LimitsTooLarge()
        {
            // A limit beyond what Argon2 allows is clamped, not rejected
            Properties.WithThreadProperty(Properties.Argon2MaxMemoryExp, "31", () =>
            Properties.WithThreadProperty(Properties.Argon2MaxParallelism, (1 << 24).ToString(), () =>
            {
                var builder = new Argon2Parameters.Builder(Argon2Parameters.Argon2id, trusted: false);
                builder.WithMemoryPowOfTwo(30).WithParallelism((1 << 24) - 1);
                Assert.Throws<ArgumentOutOfRangeException>(() => builder.WithMemoryPowOfTwo(31));
                Assert.Throws<ArgumentOutOfRangeException>(() => builder.WithParallelism(1 << 24));
            }));
        }

        [Test]
        public void CheckArgon2MinimumMemory()
        {
            // RFC 9106 sec. 3.1: memory must be at least 8 * parallelism KiB, whichever is set first
            new Argon2Parameters.Builder().WithParallelism(4).WithMemoryAsKB(32).Build();
            Assert.Throws<InvalidOperationException>(
                () => new Argon2Parameters.Builder().WithParallelism(4).WithMemoryAsKB(31).Build());
            Assert.Throws<InvalidOperationException>(
                () => new Argon2Parameters.Builder().WithMemoryAsKB(31).WithParallelism(4).Build());

            // the setters reject memory below the minimum for a single lane straight away
            Assert.Throws<ArgumentOutOfRangeException>(() => new Argon2Parameters.Builder().WithMemoryAsKB(7));
            Assert.Throws<ArgumentOutOfRangeException>(() => new Argon2Parameters.Builder().WithMemoryPowOfTwo(2));

            Properties.WithThreadProperty(Properties.Argon2AllowLegacyMemory, "true", () =>
            {
                new Argon2Parameters.Builder().WithParallelism(4).WithMemoryAsKB(31).Build();
                new Argon2Parameters.Builder().WithMemoryPowOfTwo(0).Build();
                new Argon2Parameters.Builder().WithMemoryAsKB(1).Build();

                // but not for untrusted cost parameters
                var untrusted = new Argon2Parameters.Builder(Argon2Parameters.Argon2id, trusted: false);
                untrusted.WithParallelism(4).WithMemoryAsKB(31);
                Assert.Throws<InvalidOperationException>(() => untrusted.Build());
                Assert.Throws<ArgumentOutOfRangeException>(() => untrusted.WithMemoryPowOfTwo(2));
            });
        }

        private static void ImplCheckArgon2LimitTooSmall(string propertyName, string propertyValue,
            bool appliesWhenTrusted)
        {
            Properties.WithThreadProperty(propertyName, propertyValue, () =>
            {
                var e = Assert.Throws<InvalidOperationException>(
                    () => new Argon2Parameters.Builder(Argon2Parameters.Argon2id, trusted: false));
                Assert.AreEqual(propertyName + " out of range", e.Message);

                if (appliesWhenTrusted)
                {
                    Assert.Throws<InvalidOperationException>(
                        () => new Argon2Parameters.Builder(Argon2Parameters.Argon2id));
                }
                else
                {
                    Assert.DoesNotThrow(() => new Argon2Parameters.Builder(Argon2Parameters.Argon2id));
                }
            });
        }

        #region "Block pool tests"
        // A FixedBlockPool with capacity smaller than the working set must still
        // produce correct output - excess deallocations are silently dropped.
        [Test]
        public void CustomBlockPoolBoundedDropsOverflow()
        {
            byte[] expected = HashWithPool(null);

            // capacity of 1 forces all but a single deallocate to be dropped
            byte[] result = HashWithPool(Argon2BytesGenerator.FixedBlockPool.Create(1));

            Assert.IsTrue(Arrays.AreEqual(expected, result), "undersized pool produced wrong hash");

            // and with no capacity at all
            result = HashWithPool(Argon2BytesGenerator.FixedBlockPool.Create(0));

            Assert.IsTrue(Arrays.AreEqual(expected, result), "empty pool produced wrong hash");

            Assert.Throws<ArgumentOutOfRangeException>(() => Argon2BytesGenerator.FixedBlockPool.Create(-1));
        }

        // A user-supplied pool must produce identical output to the default - no leftover state from prior calls.
        [Test]
        public void CustomBlockPoolMatchesDefault()
        {
            byte[] expected = HashWithPool(null);

            var pool = Argon2BytesGenerator.FixedBlockPool.Create(64);
            for (int run = 1; run <= 3; ++run)
            {
                Assert.IsTrue(Arrays.AreEqual(expected, HashWithPool(pool)),
                    "hash {0} with custom pool differs from default", run);
            }
        }

        // A correctly-sized custom pool should never need to allocate fresh blocks
        // after the first call - subsequent calls only recycle.
        [Test]
        public void CustomBlockPoolReusesBlocks()
        {
            var pool = new CountingBlockPool();

            HashWithPool(pool);
            int afterFirst = pool.Fresh;
            Assert.Greater(afterFirst, 0, "pool produced no fresh blocks on first call");

            for (int run = 2; run <= 3; ++run)
            {
                HashWithPool(pool);
                Assert.AreEqual(afterFirst, pool.Fresh, "pool allocated extra blocks on recycled run {0}", run);
            }
        }

        // The generator mustn't rely on what a pool hands out being zeroed.
        [Test]
        public void DirtyBlocksFromPool()
        {
            byte[] expected = HashWithPool(null);

            Assert.IsTrue(Arrays.AreEqual(expected, HashWithPool(new DirtyBlockPool())),
                "hash with blocks handed out dirty differs from default");
        }

        // The generator zeroises a block before handing it back, so a pool that clears nothing - as a
        // custom implementation is entitled to be - never sees password-derived data.
        [Test]
        public void BlocksClearedOnDeallocate()
        {
            var pool = new CheckingBlockPool();

            HashWithPool(pool);

            Assert.Greater(pool.Deallocated, 0, "no blocks were returned to the pool");
            Assert.AreEqual(0, pool.Dirty, "blocks returned to the pool carrying data");

            // and again on a run that recycles, where the blocks arrive with the previous run's data
            pool.Deallocated = 0;

            HashWithPool(pool, taskFactory: Task.Factory);

            Assert.Greater(pool.Deallocated, 0, "no blocks were returned on the second run");
            Assert.AreEqual(0, pool.Dirty, "blocks returned to the pool carrying data on a recycled run");
        }

        // GetBlockCount() is the number a pool must hold to recycle a whole run: the aligned primary
        // memory plus the fill step's working blocks. Compare it against what the generator asks for.
        [TestCase(32, 4)]
        [TestCase(32, 1)]
        [TestCase(8, 4)]
        [TestCase(1, 4)]
        [TestCase(4096, 2)]
        [TestCase(100, 3)]
        public void BlockCountMatchesTheBlocksTaken(int memory, int lanes)
        {
            // memory below 8 * lanes KiB (padded up to that by the generator) needs the legacy opt-out
            Properties.WithThreadProperty(Properties.Argon2AllowLegacyMemory, "true", () =>
            {
                byte[] expected = HashWithPool(null, memory, lanes);

                // exact only with a task for every lane (one lane is filled in turn whatever the TaskFactory)
                CheckBlockCount(expected, memory, lanes, taskFactory: null, exact: lanes == 1);
                CheckBlockCount(expected, memory, lanes, Task.Factory, exact: false);
                CheckBlockCount(expected, memory, lanes, new TaskFactory(new TestTaskScheduler(lanes)), exact: true);
            });
        }

        private static void CheckBlockCount(byte[] expected, int memory, int lanes, TaskFactory taskFactory,
            bool exact)
        {
            int blockCount = Argon2BytesGenerator.GetBlockCount(memory, lanes);

            var pool = new CountingBlockPool();

            for (int run = 1; run <= 2; ++run)
            {
                Assert.IsTrue(Arrays.AreEqual(expected, HashWithPool(pool, memory, lanes, taskFactory)),
                    "hash {0} with a counting pool differs from the default", run);

                if (exact)
                {
                    Assert.AreEqual(blockCount, pool.Fresh, "GetBlockCount() differs from the blocks taken");
                }
                else
                {
                    Assert.LessOrEqual(pool.Fresh, blockCount, "GetBlockCount() is less than the blocks taken");
                }
                Assert.AreEqual(pool.Fresh, pool.Available, "blocks not returned to the pool (run {0})", run);
            }

            // a pool of that size recycles every block of the next run
            var sized = Argon2BytesGenerator.FixedBlockPool.Create(blockCount);
            for (int run = 1; run <= 2; ++run)
            {
                Assert.IsTrue(Arrays.AreEqual(expected, HashWithPool(sized, memory, lanes, taskFactory)),
                    "hash {0} with a pool sized by GetBlockCount() differs from the default", run);
            }
        }

        [Test]
        public void BlockCountArguments()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => Argon2BytesGenerator.GetBlockCount(32, 0));
            Assert.Throws<ArgumentOutOfRangeException>(() => Argon2BytesGenerator.GetBlockCount(32, 1 << 24));
            Assert.Throws<ArgumentOutOfRangeException>(() => Argon2BytesGenerator.GetBlockCount(0, 1));
            Assert.Throws<ArgumentOutOfRangeException>(() => Argon2BytesGenerator.GetBlockCount((1 << 30) + 1, 1));

            // the largest arguments mustn't overflow
            Assert.Greater(Argon2BytesGenerator.GetBlockCount(1 << 30, 1), 1 << 30);
            Assert.Greater(Argon2BytesGenerator.GetBlockCount(1 << 30, (1 << 24) - 1), 1 << 30);
        }

        // A run that fails part way through must still return what it took, zeroised.
        [Test]
        public void BlocksReturnedAndClearedOnFailure()
        {
            var counting = new CountingBlockPool();
            HashWithPool(counting);
            int blocksTaken = counting.Fresh;

            // fail while taking the primary memory, and while taking the fill step's blocks (the last taken), by
            // which time the first blocks of each lane hold password-derived data
            foreach (int failAfter in new int[] { 0, 5, blocksTaken - 2 })
            {
                var pool = new CheckingBlockPool { FailAfter = failAfter };

                var e = Assert.Throws<InvalidOperationException>(() => HashWithPool(pool));
                Assert.AreEqual("no more blocks", e.Message);

                Assert.AreEqual(failAfter, pool.Allocated);
                Assert.AreEqual(pool.Allocated, pool.Deallocated, "blocks taken before the failure not returned");
                Assert.AreEqual(0, pool.Dirty, "blocks returned carrying data after a failed run");
            }
        }

        // The lanes are shared among no more tasks than the scheduler says it can run at once.
        [TestCase(1)]
        [TestCase(2)]
        [TestCase(3)]
        [TestCase(4)]
        [TestCase(int.MaxValue)]
        public void TasksBoundedBySchedulerConcurrency(int maxConcurrencyLevel)
        {
            const int Lanes = 4, Iterations = 3, Slices = 4;

            byte[] expected = HashWithPool(null, lanes: Lanes);

            var scheduler = new TestTaskScheduler(maxConcurrencyLevel);
            var taskFactory = new TaskFactory(scheduler);
            var pool = new CountingBlockPool();

            Assert.IsTrue(Arrays.AreEqual(expected, HashWithPool(pool, lanes: Lanes, taskFactory: taskFactory)),
                "hash with tasks bounded by the scheduler differs from the default");

            // a scheduler that sets no limit gets one task per processor
            int tasksPerSlice = maxConcurrencyLevel == int.MaxValue
                ? System.Math.Min(Lanes, Environment.ProcessorCount)
                : System.Math.Min(Lanes, maxConcurrencyLevel);
            Assert.AreEqual(Iterations * Slices * tasksPerSlice, scheduler.Queued.Count);

            Assert.LessOrEqual(pool.Fresh, Argon2BytesGenerator.GetBlockCount(32, Lanes));
        }

        // If a task can't be started, the tasks already started must finish before the blocks go back.
        [Test]
        public void StartedTasksFinishBeforeBlocksReturned()
        {
            var pool = new CheckingBlockPool();
            var scheduler = new TestTaskScheduler(maxConcurrencyLevel: 4, failAt: 2, delay: 100);
            var taskFactory = new TaskFactory(scheduler);

            Assert.Throws<TaskSchedulerException>(() => HashWithPool(pool, lanes: 4, taskFactory: taskFactory));

            Assert.AreEqual(2, scheduler.Queued.Count);
            foreach (Task task in scheduler.Queued)
            {
                Assert.IsTrue(task.IsCompleted, "a started task was still running after GenerateBytes threw");
            }

            Assert.AreEqual(pool.Allocated, pool.Deallocated, "blocks taken before the failure not returned");
            Assert.AreEqual(0, pool.Dirty, "blocks returned carrying data after a failed run");
        }

#if NETCOREAPP3_0_OR_GREATER
        // Without a pool, a generator keeps its blocks between calls (and across an Init that doesn't change the
        // memory size) rather than allocating them again.
        [Test]
        public void DefaultKeepsItsBlocks()
        {
            const int Memory = 1024;

            var gen = new Argon2BytesGenerator();
            byte[] first = HashWith(gen, null, Memory, lanes: 1);

            long before = GC.GetAllocatedBytesForCurrentThread();
            byte[] second = HashWith(gen, null, Memory, lanes: 1);
            long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

            Assert.IsTrue(Arrays.AreEqual(first, second), "second hash differs from the first");
            Assert.Less(allocated, Memory * 1024 / 8, "the second call allocated its memory again");
        }
#endif

        // A generator re-initialised across memory sizes, and between its own blocks and a pool's, matches a new one.
        [Test]
        public void ReinitAcrossSizesAndPools()
        {
            var gen = new Argon2BytesGenerator();
            var pool = new CheckingBlockPool();

            // { with pool, memory, lanes }
            int[][] configs = new int[][]
            {
                new int[] { 0, 32, 4 }, new int[] { 0, 32, 4 }, new int[] { 0, 64, 2 }, new int[] { 1, 64, 2 },
                new int[] { 1, 32, 4 }, new int[] { 0, 32, 4 }, new int[] { 1, 32, 4 }, new int[] { 0, 64, 2 },
            };

            foreach (int[] config in configs)
            {
                byte[] expected = HashWithPool(null, config[1], config[2]);
                byte[] result = HashWith(gen, config[0] != 0 ? pool : null, config[1], config[2]);

                Assert.IsTrue(Arrays.AreEqual(expected, result), "hash differs for config {{{0}}}",
                    string.Join(", ", config));
            }

            Assert.AreEqual(pool.Allocated, pool.Deallocated, "blocks taken from the pool not returned");
            Assert.AreEqual(0, pool.Dirty, "blocks returned to the pool carrying data");
        }

        // With a pool, the generator keeps no reference to a block once it has gone back.
        [Test]
        public void NoReferenceKeptToReturnedBlocks()
        {
            var pool = new TrackingBlockPool();
            var gen = new Argon2BytesGenerator();

            HashWith(gen, pool, memory: 32, lanes: 4);

            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();

            Assert.Greater(pool.Tracked.Count, 0, "no blocks were taken from the pool");
            foreach (WeakReference tracked in pool.Tracked)
            {
                Assert.IsFalse(tracked.IsAlive, "a returned block is still referenced");
            }

            GC.KeepAlive(gen);
        }

        private static byte[] HashWithPool(Argon2BytesGenerator.IBlockPool pool, int memory = 32, int lanes = 4,
            TaskFactory taskFactory = null)
        {
            return HashWith(new Argon2BytesGenerator(taskFactory), pool, memory, lanes);
        }

        private static byte[] HashWith(Argon2BytesGenerator gen, Argon2BytesGenerator.IBlockPool pool, int memory,
            int lanes)
        {
            byte[] salt = Hex.Decode("02020202020202020202020202020202");
            byte[] password = Hex.Decode("0101010101010101010101010101010101010101010101010101010101010101");

            Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
                .WithVersion(Argon2Parameters.Version13)
                .WithIterations(3)
                .WithMemoryAsKB(memory)
                .WithParallelism(lanes)
                .WithSalt(salt);

            if (pool != null)
            {
                builder.WithBlockPool(pool);
            }

            gen.Init(builder.Build());

            byte[] output = new byte[32];
            gen.GenerateBytes(password, output);
            return output;
        }

        private static bool IsClear(Argon2BytesGenerator.Block block)
        {
            foreach (ulong x in block.v)
            {
                if (x != 0UL)
                    return false;
            }
            return true;
        }

        private sealed class CountingBlockPool
            : Argon2BytesGenerator.IBlockPool
        {
            private readonly Stack<Argon2BytesGenerator.Block> m_available = new Stack<Argon2BytesGenerator.Block>();

            internal int Fresh { get; private set; }

            internal int Available => m_available.Count;

            public Argon2BytesGenerator.Block Allocate()
            {
                if (m_available.Count > 0)
                    return m_available.Pop();

                ++Fresh;
                return new Argon2BytesGenerator.Block();
            }

            public void Deallocate(Argon2BytesGenerator.Block block) => m_available.Push(block);
        }

        // Checks what it is handed rather than clearing it.
        private sealed class CheckingBlockPool
            : Argon2BytesGenerator.IBlockPool
        {
            private readonly Stack<Argon2BytesGenerator.Block> m_available = new Stack<Argon2BytesGenerator.Block>();

            internal int Allocated { get; private set; }
            internal int Deallocated { get; set; }
            internal int Dirty { get; private set; }
            internal int FailAfter { get; set; } = -1;

            public Argon2BytesGenerator.Block Allocate()
            {
                if (Allocated == FailAfter)
                    throw new InvalidOperationException("no more blocks");

                ++Allocated;
                return m_available.Count > 0 ? m_available.Pop() : new Argon2BytesGenerator.Block();
            }

            public void Deallocate(Argon2BytesGenerator.Block block)
            {
                ++Deallocated;
                if (!IsClear(block))
                {
                    ++Dirty;
                }
                m_available.Push(block);
            }
        }

        // Hands out new blocks, tracking them weakly, and drops what comes back.
        private sealed class TrackingBlockPool
            : Argon2BytesGenerator.IBlockPool
        {
            internal List<WeakReference> Tracked { get; } = new List<WeakReference>();

            public Argon2BytesGenerator.Block Allocate()
            {
                var block = new Argon2BytesGenerator.Block();
                Tracked.Add(new WeakReference(block));
                return block;
            }

            public void Deallocate(Argon2BytesGenerator.Block block)
            {
            }
        }

        // Hands out blocks full of junk.
        private sealed class DirtyBlockPool
            : Argon2BytesGenerator.IBlockPool
        {
            public Argon2BytesGenerator.Block Allocate()
            {
                var block = new Argon2BytesGenerator.Block();
                for (int i = 0; i < block.v.Length; ++i)
                {
                    block.v[i] = 0xA5A5A5A5A5A5A5A5UL ^ (ulong)i;
                }
                return block;
            }

            public void Deallocate(Argon2BytesGenerator.Block block)
            {
            }
        }

        // Reports the given concurrency level, runs each task on the thread pool (after an optional delay), and
        // refuses to queue any after the first failAt.
        private sealed class TestTaskScheduler
            : TaskScheduler
        {
            private readonly int m_maxConcurrencyLevel, m_failAt, m_delay;

            internal TestTaskScheduler(int maxConcurrencyLevel, int failAt = -1, int delay = 0)
            {
                m_maxConcurrencyLevel = maxConcurrencyLevel;
                m_failAt = failAt;
                m_delay = delay;
            }

            public override int MaximumConcurrencyLevel => m_maxConcurrencyLevel;

            // only the generator's calling thread queues tasks
            internal List<Task> Queued { get; } = new List<Task>();

            protected override IEnumerable<Task> GetScheduledTasks() => null;

            protected override void QueueTask(Task task)
            {
                if (Queued.Count == m_failAt)
                    throw new InvalidOperationException("no more tasks");

                Queued.Add(task);
                ThreadPool.QueueUserWorkItem(_ =>
                {
                    if (m_delay > 0)
                    {
                        Thread.Sleep(m_delay);
                    }
                    TryExecuteTask(task);
                });
            }

            protected override bool TryExecuteTaskInline(Task task, bool taskWasPreviouslyQueued) => false;
        }
        #endregion
    }
}
