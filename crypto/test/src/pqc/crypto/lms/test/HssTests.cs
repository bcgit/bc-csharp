using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pqc.Crypto.Lms.Tests
{
    [TestFixture]
    public class HssTests
    {
        [Test]
        public void TestHssKeySerialisation()
        {
            byte[] fixedSource = new byte[8192];
            for (int t = 0; t < fixedSource.Length; t++)
            {
                fixedSource[t] = 1;
            }

            FixedSecureRandom.Source[] source = { new FixedSecureRandom.Source(fixedSource) };
            SecureRandom rand = new FixedSecureRandom(source);

            HssPrivateKeyParameters generatedPrivateKey = Hss.GenerateHssKeyPair(
                new HssKeyGenerationParameters(new LmsParameters[]
                {
                    new LmsParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                    new LmsParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w2),
                }, rand)
            );

            HssSignature sigFromGeneratedPrivateKey = Hss.GenerateSignature(generatedPrivateKey, Hex.Decode("ABCDEF"));

            byte[] keyPairEnc = generatedPrivateKey.GetEncoded();

            HssPrivateKeyParameters reconstructedPrivateKey = HssPrivateKeyParameters.GetInstance(keyPairEnc);
            Assert.True(reconstructedPrivateKey.Equals(generatedPrivateKey));

            reconstructedPrivateKey.GetPublicKey();
            generatedPrivateKey.GetPublicKey();

            //
            // Are they still equal, public keys are only checked if they both
            // exist because they are only created when requested as they are derived from the private key.
            //
            Assert.True(reconstructedPrivateKey.Equals(generatedPrivateKey));

            //
            // Check the reconstructed key can verify a signature.
            //
            Assert.True(Hss.VerifySignature(reconstructedPrivateKey.GetPublicKey(), sigFromGeneratedPrivateKey,
                Hex.Decode("ABCDEF")));
        }

        /**
         * Test Case 1 Signature
         * From https://tools.ietf.org/html/rfc8554#appendix-F
         */
        [Test]
        public void TestHssVector_1()
        {
            var blocks = LoadTestResource("pqc/crypto/lms/testcase_1.txt");

            HssPublicKeyParameters publicKey = HssPublicKeyParameters.GetInstance(blocks[0]);
            byte[] message = blocks[1];
            HssSignature signature = HssSignature.GetInstance(blocks[2], publicKey.Level);
            Assert.True(Hss.VerifySignature(publicKey, signature, message), "Test Case 1 ");
        }

        /**
         * Test Case 1 Signature
         * From https://tools.ietf.org/html/rfc8554#appendix-F
         */
        [Test]
        public void TestHssVector_2()
        {
            var blocks = LoadTestResource("pqc/crypto/lms/testcase_2.txt");

            HssPublicKeyParameters publicKey = HssPublicKeyParameters.GetInstance(blocks[0]);
            byte[] message = blocks[1];
            byte[] sig = blocks[2];
            HssSignature signature = HssSignature.GetInstance(sig, publicKey.Level);
            Assert.True(Hss.VerifySignature(publicKey, signature, message), "Test Case 2 Signature");

            LmsPublicKeyParameters lmsPub = LmsPublicKeyParameters.GetInstance(blocks[3]);
            LmsSignature lmsSignature = LmsSignature.GetInstance(blocks[4]);

            Assert.True(Lms.VerifySignature(lmsPub, lmsSignature, message), "Test Case 2 Signature 2");
        }

        private IList<byte[]> LoadTestResource(string path)
        {
            StreamReader bin = new StreamReader(SimpleTest.FindTestResource(path));
            var blocks = new List<byte[]>();
            StringBuilder sw = new StringBuilder();

            string line;
            while ((line = bin.ReadLine()) != null)
            {
                if (line.StartsWith("!"))
                {
                    if (sw.Length > 0)
                    {
                        blocks.Add(LmsVectorUtilities.ExtractPrefixedBytes(sw.ToString()));
                        sw.Length = 0;
                    }
                }
                sw.Append(line);
                sw.Append("\n");
            }

            if (sw.Length > 0)
            {
                blocks.Add(LmsVectorUtilities.ExtractPrefixedBytes(sw.ToString()));
                sw.Length = 0;
            }
            return blocks;
        }

        /**
         * Test the generation of public keys from private key SEED and I.
         * Level 0
         */
        [Test]
        public void TestGenPublicKeys_L0()
        {
            byte[] seed = Hex.Decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
            int level = 0;
            LmsPrivateKeyParameters lmsPrivateKey = Lms.GenerateKeys(LMSigParameters.GetParametersByID(6),
                LMOtsParameters.GetParametersByID(3), level, Hex.Decode("d08fabd4a2091ff0a8cb4ed834e74534"), seed);
            LmsPublicKeyParameters publicKey = lmsPrivateKey.GetPublicKey();
            Assert.True(Arrays.AreEqual(publicKey.GetT1(),
                Hex.Decode("32a58885cd9ba0431235466bff9651c6c92124404d45fa53cf161c28f1ad5a8e")));
            Assert.True(Arrays.AreEqual(publicKey.GetI(), Hex.Decode("d08fabd4a2091ff0a8cb4ed834e74534")));
        }

        /**
         * Test the generation of public keys from private key SEED and I.
         * Level 1;
         */
        [Test]
        public void TestGenPublicKeys_L1()
        {
            byte[] seed = Hex.Decode("a1c4696e2608035a886100d05cd99945eb3370731884a8235e2fb3d4d71f2547");
            int level = 1;
            LmsPrivateKeyParameters lmsPrivateKey = Lms.GenerateKeys(LMSigParameters.GetParametersByID(5),
                LMOtsParameters.GetParametersByID(4), level, Hex.Decode("215f83b7ccb9acbcd08db97b0d04dc2b"), seed);
            LmsPublicKeyParameters publicKey = lmsPrivateKey.GetPublicKey();
            Assert.True(Arrays.AreEqual(publicKey.GetT1(),
                Hex.Decode("a1cd035833e0e90059603f26e07ad2aad152338e7a5e5984bcd5f7bb4eba40b7")));
            Assert.True(Arrays.AreEqual(publicKey.GetI(), Hex.Decode("215f83b7ccb9acbcd08db97b0d04dc2b")));
        }

        [Test]
        public void TestGenerate()
        {
            //
            // Generate an HSS key pair for a two level HSS scheme.
            // then use that to verify it compares with a value from the same reference implementation.
            // Then check components of it serialize and deserialize properly.
            //
            byte[] fixedSource = new byte[8192];
            for (int t = 0; t < fixedSource.Length; t++)
            {
                fixedSource[t] = 1;
            }

            FixedSecureRandom.Source[] source = { new FixedSecureRandom.Source(fixedSource) };
            SecureRandom rand = new FixedSecureRandom(source);

            HssPrivateKeyParameters keyPair = Hss.GenerateHssKeyPair(
                new HssKeyGenerationParameters(new LmsParameters[]
                {
                    new LmsParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                    new LmsParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w2),
                }, rand));

            //
            // Generated from reference implementation.
            // check the encoded form of the public key matches.
            //
            string expectedPk =
                "0000000200000005000000030101010101010101010101010101010166BF6F5816EEE4BBF33C50ACB480E09B4169EBB533372959BC4315C388E501AC";
            byte[] pkEnc = keyPair.GetPublicKey().GetEncoded();
            Assert.True(Arrays.AreEqual(Hex.Decode(expectedPk), pkEnc));

            //
            // Check that HSS public keys have value equality after deserialization.
            // Use external sourced pk for deserialization.
            //
            Assert.True(keyPair.GetPublicKey().Equals(HssPublicKeyParameters.GetInstance(Hex.Decode(expectedPk))),
                "HSSPrivateKeyParameterss equal are deserialization");

            //
            // Generate, hopefully the same HSSKetPair for the same entropy.
            // This is a sanity test
            //
            {
                FixedSecureRandom.Source[] source1 = { new FixedSecureRandom.Source(fixedSource) };
                SecureRandom rand1 = new FixedSecureRandom(source1);

                HssPrivateKeyParameters regenKeyPair = Hss.GenerateHssKeyPair(
                    new HssKeyGenerationParameters(new LmsParameters[]
                    {
                        new LmsParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                        new LmsParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w2),
                    }, rand1));

                Assert.True(
                    Arrays.AreEqual(regenKeyPair.GetPublicKey().GetEncoded(), keyPair.GetPublicKey().GetEncoded()),
                    "Both generated keys are the same");

                Assert.True(keyPair.GetKeys().Count == regenKeyPair.GetKeys().Count,
                    "same private key size");

                for (int t = 0; t < keyPair.GetKeys().Count; t++)
                {
                    //
                    // Check the private keys can be encoded and are the same.
                    //
                    byte[] pk1 = keyPair.GetKeys()[t].GetEncoded();
                    byte[] pk2 = regenKeyPair.GetKeys()[t].GetEncoded();
                    Assert.True(Arrays.AreEqual(pk1, pk2));

                    //
                    // Deserialize them and see if they still equal.
                    //
                    LmsPrivateKeyParameters pk1O = LmsPrivateKeyParameters.GetInstance(pk1);
                    LmsPrivateKeyParameters pk2O = LmsPrivateKeyParameters.GetInstance(pk2);

                    Assert.True(pk1O.Equals(pk2O), "LmsPrivateKey still equal after deserialization");

                }
            }

            //
            // This time we will generate another set of keys using a different entropy source.
            // they should be different!
            // Useful for detecting accidental hard coded things.
            //

            {
                // Use a real secure random this time.
                SecureRandom rand1 = new SecureRandom();

                HssPrivateKeyParameters differentKey = Hss.GenerateHssKeyPair(
                    new HssKeyGenerationParameters(new LmsParameters[]
                    {
                        new LmsParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                        new LmsParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w2),
                    }, rand1)
                );

                Assert.False(
                    Arrays.AreEqual(differentKey.GetPublicKey().GetEncoded(), keyPair.GetPublicKey().GetEncoded()),
                    "Both generated keys are not the same");

                for (int t = 0; t < keyPair.GetKeys().Count; t++)
                {
                    //
                    // Check the private keys can be encoded and are not the same.
                    //
                    byte[] pk1 = keyPair.GetKeys()[t].GetEncoded();
                    byte[] pk2 = differentKey.GetKeys()[t].GetEncoded();
                    Assert.False(Arrays.AreEqual(pk1, pk2), "keys not the same");

                    //
                    // Deserialize them and see if they still equal.
                    //
                    LmsPrivateKeyParameters pk1O = LmsPrivateKeyParameters.GetInstance(pk1);
                    LmsPrivateKeyParameters pk2O = LmsPrivateKeyParameters.GetInstance(pk2);

                    Assert.False(pk1O.Equals(pk2O), "LmsPrivateKey not suddenly equal after deserialization");
                }
            }
        }

        /**
         * This test takes in a series of vectors generated by adding print statements to code called by
         * the "test_sign.c" test in the reference implementation.
         * <p>
         * The purpose of this test is to ensure that the signatures and public keys exactly match for the
         * same entropy source the values generated by the reference implementation.
         * <p>
         * It also verifies value equality between signature and public key objects as well as
         * complimentary serialization and deserialization.
         *
         * @
         */
        [Test]
        public void TestVectorsFromReference()
        {
            StreamReader sr = new StreamReader(SimpleTest.FindTestResource("pqc/crypto/lms/depth_1.txt"));

            var lmsParameters = new List<LMSigParameters>();
            var lmOtsParameters = new List<LMOtsParameters>();
            byte[] message = null;
            byte[] hssPubEnc = null;
            MemoryStream fixedESBuffer = new MemoryStream();
            int d = 0, j = 0;

            string line;
            while ((line = sr.ReadLine()) != null)
            {
                if (TrimLine(ref line))
                    continue;

                if (line.StartsWith("Depth:"))
                {
                    d = int.Parse(line.Substring("Depth:".Length).Trim());
                }
                else if (line.StartsWith("LMType:"))
                {
                    int typ = int.Parse(line.Substring("LMType:".Length).Trim());
                    lmsParameters.Add(LMSigParameters.GetParametersByID(typ));
                }
                else if (line.StartsWith("LMOtsType:"))
                {
                    int typ = int.Parse(line.Substring("LMOtsType:".Length).Trim());
                    lmOtsParameters.Add(LMOtsParameters.GetParametersByID(typ));
                }
                else if (line.StartsWith("Rand:"))
                {
                    var b = Hex.Decode(line.Substring("Rand:".Length).Trim());
                    fixedESBuffer.Write(b, 0, b.Length);
                }
                else if (line.StartsWith("HSSPublicKey:"))
                {
                    hssPubEnc = Hex.Decode(line.Substring("HSSPublicKey:".Length).Trim());
                }
                else if (line.StartsWith("Message:"))
                {
                    message = Hex.Decode(line.Substring("Message:".Length).Trim());
                }
                else if (line.StartsWith("Signature:"))
                {
                    j++;

                    byte[] encodedSigFromVector = Hex.Decode(line.Substring("Signature:".Length).Trim());

                    //
                    // Assumes Signature is the last element in the set of vectors.
                    //
                    FixedSecureRandom.Source[] source = { new FixedSecureRandom.Source(fixedESBuffer.ToArray()) };
                    FixedSecureRandom fixRnd = new FixedSecureRandom(source);
                    fixedESBuffer.SetLength(0);//todo is this correct? buffer.reset();
                    //fixedESBuffer = new MemoryStream();

                    //
                    // Deserialize pub key from reference impl.
                    //
                    HssPublicKeyParameters vectorSourcedPubKey = HssPublicKeyParameters.GetInstance(hssPubEnc);
                    var lmsParams = new List<LmsParameters>();

                    for (int i = 0; i != lmsParameters.Count; i++)
                    {
                        lmsParams.Add(new LmsParameters(lmsParameters[i], lmOtsParameters[i]));
                    }

                    //
                    // Using our fixed entropy source generate hss keypair
                    //

                    LmsParameters[] lmsParamsArray = new LmsParameters[lmsParams.Count];
                    lmsParams.CopyTo(lmsParamsArray, 0);
                    HssPrivateKeyParameters keyPair = Hss.GenerateHssKeyPair(
                        new HssKeyGenerationParameters(
                            lmsParamsArray, fixRnd)
                    );

                    {
                        // Public Key should match vector.

                        // Encoded value equality.
                        HssPublicKeyParameters generatedPubKey = keyPair.GetPublicKey();
                        Assert.True(Arrays.AreEqual(hssPubEnc, generatedPubKey.GetEncoded()));

                        // Value equality.
                        Assert.True(vectorSourcedPubKey.Equals(generatedPubKey));
                    }

                    //
                    // Generate a signature using the keypair we generated.
                    //
                    HssSignature sig = Hss.GenerateSignature(keyPair, message);

                    HssSignature signatureFromVector = null;
                    if (!Arrays.AreEqual(sig.GetEncoded(), encodedSigFromVector))
                    {
                        signatureFromVector = HssSignature.GetInstance(encodedSigFromVector, d);
                        signatureFromVector.Equals(sig);
                    }

                    // check encoding signature matches.
                    Assert.True(Arrays.AreEqual(sig.GetEncoded(), encodedSigFromVector));

                    // Check we can verify our generated signature with the vectors sourced public key.
                    Assert.True(Hss.VerifySignature(vectorSourcedPubKey, sig, message));

                    // Deserialize the signature from the vector.
                    signatureFromVector = HssSignature.GetInstance(encodedSigFromVector, d);

                    // Can we verify signature from vector with public key from vector.
                    Assert.True(Hss.VerifySignature(vectorSourcedPubKey, signatureFromVector, message));

                    //
                    // Check our generated signature and the one deserialized from the vector
                    // have value equality.
                    Assert.True(signatureFromVector.Equals(sig));

                    //
                    // Other tests vandalise HSS signatures to check they Assert.Fail when tampered with
                    // we won't do that again here.
                    //
                    d = 0;
                    lmOtsParameters.Clear();
                    lmsParameters.Clear();
                    message = null;
                    hssPubEnc = null;
                }
            }
        }

        [Test]
        public void TestVectorsFromReference_Expanded()
        {
            using (StreamReader sr = new StreamReader(SimpleTest.FindTestResource("pqc/crypto/lms/expansion.txt")))
            {
                var lmsParameters = new List<LMSigParameters>();
                var lmOtsParameters = new List<LMOtsParameters>();
                byte[] message = null;
                byte[] hssPubEnc = null;
                MemoryStream fixedESBuffer = new MemoryStream();
                var sigVectors = new List<byte[]>();
                int d = 0;

                string line;
                while ((line = sr.ReadLine()) != null)
                {
                    if (TrimLine(ref line))
                        continue;

                    if (line.StartsWith("Depth:"))
                    {
                        d = int.Parse(line.Substring("Depth:".Length).Trim());
                    }
                    else if (line.StartsWith("LMType:"))
                    {
                        int typ = int.Parse(line.Substring("LMType:".Length).Trim());
                        lmsParameters.Add(LMSigParameters.GetParametersByID(typ));
                    }
                    else if (line.StartsWith("LMOtsType:"))
                    {
                        int typ = int.Parse(line.Substring("LMOtsType:".Length).Trim());
                        lmOtsParameters.Add(LMOtsParameters.GetParametersByID(typ));
                    }
                    else if (line.StartsWith("Rand:"))
                    {
                        var b = Hex.Decode(line.Substring("Rand:".Length).Trim());
                        fixedESBuffer.Write(b, 0, b.Length);
                    }
                    else if (line.StartsWith("HSSPublicKey:"))
                    {
                        hssPubEnc = Hex.Decode(line.Substring("HSSPublicKey:".Length).Trim());
                    }
                    else if (line.StartsWith("Message:"))
                    {
                        message = Hex.Decode(line.Substring("Message:".Length).Trim());

                    }
                    else if (line.StartsWith("Signature:"))
                    {
                        sigVectors.Add(Hex.Decode(line.Substring("Signature:".Length).Trim()));
                    }
                }

                //
                // Assumes Signature is the last element in the set of vectors.
                //
                FixedSecureRandom.Source[] source = { new FixedSecureRandom.Source(fixedESBuffer.ToArray()) };
                FixedSecureRandom fixRnd = new FixedSecureRandom(source);
                fixedESBuffer.SetLength(0);
                var lmsParams = new List<LmsParameters>();

                for (int i = 0; i != lmsParameters.Count; i++)
                {
                    lmsParams.Add(new LmsParameters(lmsParameters[i], lmOtsParameters[i]));
                }

                LmsParameters[] lmsParamsArray = new LmsParameters[lmsParams.Count];
                lmsParams.CopyTo(lmsParamsArray, 0);
                HssPrivateKeyParameters keyPair = Hss.GenerateHssKeyPair(
                    new HssKeyGenerationParameters(lmsParamsArray, fixRnd)
                );

                Assert.True(Arrays.AreEqual(hssPubEnc, keyPair.GetPublicKey().GetEncoded()));

                HssPublicKeyParameters pubKeyFromVector = HssPublicKeyParameters.GetInstance(hssPubEnc);
                HssPublicKeyParameters pubKeyGenerated = null;


                Assert.AreEqual(1024, keyPair.GetUsagesRemaining());
                Assert.AreEqual(1024, keyPair.IndexLimit);

                //
                // Split the space up with a shard.
                //

                HssPrivateKeyParameters shard1 = keyPair.ExtractKeyShard(500);
                pubKeyGenerated = shard1.GetPublicKey();


                HssPrivateKeyParameters pair = shard1;

                int c = 0;
                for (int i = 0; i < keyPair.IndexLimit; i++)
                {
                    if (i == 500)
                    {
                        try
                        {
                            Hss.IncrementIndex(pair);
                            Assert.Fail("shard should be exhausted.");
                        }
                        catch (Exception ex)
                        {
                            Assert.AreEqual("hss private key shard is exhausted", ex.Message);
                        }

                        pair = keyPair;
                        pubKeyGenerated = keyPair.GetPublicKey();

                        Assert.AreEqual(pubKeyGenerated, shard1.GetPublicKey());
                    }

                    if (i % 5 == 0)
                    {
                        HssSignature sigCalculated = Hss.GenerateSignature(pair, message);
                        Assert.True(Arrays.AreEqual(sigCalculated.GetEncoded(), sigVectors[c]));

                        Assert.True(Hss.VerifySignature(pubKeyFromVector, sigCalculated, message));
                        Assert.True(Hss.VerifySignature(pubKeyGenerated, sigCalculated, message));

                        HssSignature sigFromVector = HssSignature.GetInstance(sigVectors[c],
                            pubKeyFromVector.Level);

                        Assert.True(Hss.VerifySignature(pubKeyFromVector, sigFromVector, message));
                        Assert.True(Hss.VerifySignature(pubKeyGenerated, sigFromVector, message));


                        Assert.True(sigCalculated.Equals(sigFromVector));


                        c++;
                    }
                    else
                    {
                        Hss.IncrementIndex(pair);
                    }
                }
            }
        }

        /**
         * Test remaining calculation is accurate and a new key is generated when
         * all the ots keys for that level are consumed.
         *
         * @
         */
        [Test]
        public void TestRemaining()
        {
            HssPrivateKeyParameters keyPair = Hss.GenerateHssKeyPair(
                new HssKeyGenerationParameters(new LmsParameters[]
                {
                    new LmsParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w2),
                    new LmsParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w2)
                }, new SecureRandom())
            );


            LmsPrivateKeyParameters lmsKey = keyPair.GetKeys()[keyPair.L - 1];
            //
            // There should be a max of 32768 signatures for this key.
            //
            Assert.True(1024 == keyPair.GetUsagesRemaining());

            Hss.IncrementIndex(keyPair);
            Hss.IncrementIndex(keyPair);
            Hss.IncrementIndex(keyPair);
            Hss.IncrementIndex(keyPair);
            Hss.IncrementIndex(keyPair);

            Assert.True(5 == keyPair.GetIndex()); // Next key is at index 5!

            Assert.True(1024 - 5 == keyPair.GetUsagesRemaining());

            HssPrivateKeyParameters shard = keyPair.ExtractKeyShard(10);

            Assert.True(15 == shard.IndexLimit);
            Assert.True(5 == shard.GetIndex());

            // Should not be the same.
            Assert.False(shard.GetIndex() == keyPair.GetIndex());

            //
            // Should be 17 left, it will throw if it has been exhausted.
            //
            for (int t = 0; t < 17; t++)
            {
                Hss.IncrementIndex(keyPair);
            }

            // We have used 32 keys.
            Assert.True(1024 - 32 == keyPair.GetUsagesRemaining());

            Hss.GenerateSignature(keyPair, Encoding.ASCII.GetBytes("Foo"));

            //
            // This should trigger the generation of a new key.
            //
            LmsPrivateKeyParameters potentialNewLMSKey = keyPair.GetKeys()[keyPair.L - 1];
            Assert.False(potentialNewLMSKey.Equals(lmsKey));
        }

        [Test]
        public void TestSharding()
        {
            HssPrivateKeyParameters keyPair = Hss.GenerateHssKeyPair(
                new HssKeyGenerationParameters(new LmsParameters[]
                {
                    new LmsParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w2),
                    new LmsParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w2)
                }, new SecureRandom())
            );

            Assert.True(1024 == keyPair.GetUsagesRemaining());
            Assert.True(1024 == keyPair.IndexLimit);
            Assert.True(0 == keyPair.GetIndex());
            Assert.False(keyPair.IsShard());
            Hss.IncrementIndex(keyPair);


            //
            // Take a shard that should cross boundaries
            //
            HssPrivateKeyParameters shard = keyPair.ExtractKeyShard(48);
            Assert.True(shard.IsShard());
            Assert.True(48 == shard.GetUsagesRemaining());
            Assert.True(49 == shard.IndexLimit);
            Assert.True(1 == shard.GetIndex());

            Assert.True(49 == keyPair.GetIndex());


            int t = 47;
            while (--t >= 0)
            {
                Hss.IncrementIndex(shard);
            }

            HssSignature sig = Hss.GenerateSignature(shard, Encoding.ASCII.GetBytes("Cats"));

            //
            // Test it validates and nothing has gone wrong with the public keys.
            //
            Assert.True(Hss.VerifySignature(keyPair.GetPublicKey(), sig, Encoding.ASCII.GetBytes("Cats")));
            Assert.True(Hss.VerifySignature(shard.GetPublicKey(), sig, Encoding.ASCII.GetBytes("Cats")));

            // Signing again should Assert.Fail.

            try
            {
                Hss.GenerateSignature(shard, Encoding.ASCII.GetBytes("Cats"));
                Assert.Fail();
            }
            catch (Exception ex)
            {
                Assert.True(ex.Message.Equals("hss private key shard is exhausted"));
            }

            // Should work without throwing.
            Hss.GenerateSignature(keyPair, Encoding.ASCII.GetBytes("Cats"));
        }

        /**
         * Take an HSS key pair and exhaust its signing capacity.
         *
         * @
         */
        internal class HSSSecureRandom
            : SecureRandom
        {
            internal HSSSecureRandom()
                : base(null)
            {
            }

            public override void NextBytes(byte[] buf)
            {
                NextBytes(buf, 0, buf.Length);
            }

            public override void NextBytes(byte[] buf, int off, int len)
            {
                for (int t = 0; t < len; t++)
                {
                    buf[off + t] = 1;
                }
            }
        }

        [Test]
        public void TestSignUnitExhaustion()
        {
            HSSSecureRandom rand = new HSSSecureRandom();

            HssPrivateKeyParameters keyPair = Hss.GenerateHssKeyPair(
                new HssKeyGenerationParameters(new LmsParameters[]
                {
                    new LmsParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w2),
                    new LmsParameters(LMSigParameters.lms_sha256_n32_h10, LMOtsParameters.sha256_n32_w1),
                }, rand)
            );

            HssPublicKeyParameters pk = keyPair.GetPublicKey();


            int ctr = 0;
            byte[] message = new byte[32];

            //
            // There should be a max of 32768 signatures for this key.
            //

            Assert.True(keyPair.GetUsagesRemaining() == 32768);

            int mod = 256;
            try
            {
                while (ctr < 32769) // Just a number..
                {
                    if (ctr % mod == 0)
                    {
                        //
                        // We don't want to check every key.
                        // The test will take over an hour to complete.
                        //
                        Pack_Int32_To_BE(ctr, message, 0);
                        HssSignature sig = Hss.GenerateSignature(keyPair, message);

                        Assert.True(ctr % 1024 == sig.Signature.Q);

                        // Check there was a post increment in the tail end LMS key.
                        Assert.True(ctr % 1024 + 1 == keyPair.GetKeys()[keyPair.L - 1].GetIndex());

                        Assert.True(ctr + 1 == keyPair.GetIndex());


                        // Validate the heirarchial path building was correct.

                        long[] qValues = new long[keyPair.GetKeys().Count];
                        long q = ctr;

                        for (int t = keyPair.GetKeys().Count - 1; t >= 0; t--)
                        {
                            LMSigParameters sigParameters = keyPair.GetKeys()[t].SigParameters;
                            int mask = (1 << sigParameters.H) - 1;
                            qValues[t] = q & mask;
                            q >>= sigParameters.H;
                        }

                        for (int t = 0; t < keyPair.GetKeys().Count; t++)
                        {
                            Assert.True(keyPair.GetKeys()[t].GetIndex() - 1 == qValues[t]);
                        }

                        Assert.True(Hss.VerifySignature(pk, sig, message));
                        Assert.True(sig.Signature.SigParameters.ID == LMSigParameters.lms_sha256_n32_h10.ID);

                        {
                            //
                            // Vandalise hss signature.
                            //
                            byte[] rawSig = sig.GetEncoded();
                            rawSig[100] ^= 1;
                            HssSignature parsedSig = HssSignature.GetInstance(rawSig, pk.Level);
                            Assert.False(Hss.VerifySignature(pk, parsedSig, message));

                            try
                            {
                                HssSignature.GetInstance(rawSig, 0);
                                Assert.Fail();
                            }
                            catch (Exception ex)
                            {
                                Assert.True(ex.Message.Contains("nspk exceeded maxNspk"));
                            }

                        }

                        {
                            //
                            // Vandalise hss message
                            //
                            byte[] newMsg = new byte[message.Length];
                            message.CopyTo(newMsg, 0);
                            newMsg[1] ^= 1;
                            Assert.False(Hss.VerifySignature(pk, sig, newMsg));
                        }

                        {
                            //
                            // Vandalise public key
                            //
                            byte[] pkEnc = pk.GetEncoded();
                            pkEnc[35] ^= 1;
                            HssPublicKeyParameters rebuiltPk = HssPublicKeyParameters.GetInstance(pkEnc);
                            Assert.False(Hss.VerifySignature(rebuiltPk, sig, message));
                        }
                    }
                    else
                    {
                        // Skip some keys.
                        Hss.IncrementIndex(keyPair);
                    }

                    ctr++;
                }

                //System.out.Println(ctr);
                Assert.Fail();
            }
            catch (Exception ex)
            {
                Assert.True(keyPair.GetUsagesRemaining() == 0);
                Assert.True(ctr == 32768);
                Assert.True(ex.Message.Contains("hss private key is exhausted"));
            }
        }

        private static void Pack_Int32_To_BE(int n, byte[] bs, int off)
        {
            bs[off] = (byte)(n >> 24);
            bs[off + 1] = (byte)(n >> 16);
            bs[off + 2] = (byte)(n >> 8);
            bs[off + 3] = (byte)n;
        }

        private static bool TrimLine(ref string line)
        {
            int commentPos = line.IndexOf('#');
            if (commentPos >= 0)
            {
                line = line.Substring(0, commentPos);
            }

            line = line.Trim();

            return line.Length < 1;
        }
    }
}
