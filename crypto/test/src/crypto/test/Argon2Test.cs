using System;
using System.Collections.Generic;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
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
            // lanes less than MIN_PARALLELISM
            CheckInvalidConfig(b => b.WithParallelism(0));

            // lanes greater than MAX_PARALLELISM
            CheckInvalidConfig(b => b.WithParallelism(16777299));

            // iterations less than MIN_ITERATIONS
            CheckInvalidConfig(b => b.WithIterations(0));

            // memory less than 2 * lanes
            CheckInvalidConfig(b => b.WithMemoryAsKB(10).WithParallelism(6));

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
                            byte[] expected = Generate(Argon2Parameters.Argon2_Version10, 1, 8, 2, rootPassword, salt, 32);
                            byte[] testValue = Generate(Argon2Parameters.Argon2_Version10, 1, 8, 2, candidate, salt, 32);

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
            Assert.Throws<InvalidOperationException>(() =>
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
            Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.Argon2_i)
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

            int version = Argon2Parameters.Argon2_Version10;

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
            int version = Argon2Parameters.Argon2_Version13;

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
            Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.Argon2_i)
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
                Argon2Parameters.Argon2_Version13,
                Argon2Parameters.Argon2_d,
                "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb");

            SpecsTest(
                Argon2Parameters.Argon2_Version13,
                Argon2Parameters.Argon2_i,
                "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8");

            SpecsTest(
                Argon2Parameters.Argon2_Version13,
                Argon2Parameters.Argon2_id,
                "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");

            /* Version 0x10 (16) from reference C implementation https://github.com/P-H-C/phc-winner-argon2/tree/master/kats */
            SpecsTest(
                Argon2Parameters.Argon2_Version10,
                Argon2Parameters.Argon2_d,
                "96a9d4e5a1734092c85e29f410a45914a5dd1f5cbf08b2670da68a0285abf32b");

            SpecsTest(
                Argon2Parameters.Argon2_Version10,
                Argon2Parameters.Argon2_i,
                "87aeedd6517ab830cd9765cd8231abb2e647a5dee08f7c05e02fcb763335d0fd");

            SpecsTest(
                Argon2Parameters.Argon2_Version10,
                Argon2Parameters.Argon2_id,
                "b64615f07789b66b645b67ee9ed3b377ae350b6bfcbb0fc95141ea8f322613c0");
        }
        #endregion
    }
}
