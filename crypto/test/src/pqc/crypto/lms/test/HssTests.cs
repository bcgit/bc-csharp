using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Utilities;
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
        public void HssKeySerialisation()
        {
            byte[] fixedSource = new byte[8192];
            for (int t = 0; t < fixedSource.Length; t++)
            {
                fixedSource[t] = 1;
            }

            FixedSecureRandom.Source[] source = { new FixedSecureRandom.Source(fixedSource) };
            SecureRandom rand = new FixedSecureRandom(source);

            HssPrivateKeyParameters generatedPrivateKey = LmsTestUtilities.GenerateHssPrivateKey(
                new HssKeyGenerationParameters(new LmsParameters[]
                {
                    LmsParameters.Create(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                    LmsParameters.Create(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w2),
                }, rand)
            );

            HssSignature sigFromGeneratedPrivateKey = LmsTestUtilities.GenerateHssSignature(generatedPrivateKey,
                Hex.Decode("ABCDEF"));

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
            Assert.True(LmsTestUtilities.VerifyHssSignature(reconstructedPrivateKey.GetPublicKey(),
                sigFromGeneratedPrivateKey, Hex.Decode("ABCDEF")));
        }

        /**
         * A multi-level HSS private key in the version 0 encoding - written by any release before the tree-cache
         * feature, whose component keys end at the master secret - must still decode and sign. The component
         * keys share one stream, so the cache cannot be detected from "more bytes available": the encoding
         * version tells the parser whether the cache field is present (bc-java github #2365).
         */
        [Test]
        public void Version0HssKeyDecodes()
        {
            ImplVersion0HssKeyDecodes(1);
            ImplVersion0HssKeyDecodes(2);
            ImplVersion0HssKeyDecodes(3);
        }

        private void ImplVersion0HssKeyDecodes(int d)
        {
            HssPrivateKeyParameters generated = GenerateKey(d);

            // Rewrite the version 1 encoding into what a pre-tree-cache release wrote: version 0, each component
            // key ending at its master secret, with the chaining signatures unchanged.
            byte[] enc = generated.GetEncoded();
            Composer composer = Composer.Compose()
                .U32Str(0) // version 0: pre-tree-cache component keys
                .Bytes(enc, 4, 21); // l, index, indexLimit, isShard - unchanged
            int pos = 25;
            for (int t = 0; t < d; t++)
            {
                int m = LMSigParameters.GetParametersByID((int)Pack.BE_To_UInt32(enc, pos + 4)).M;
                // up to and including the master secret
                int keyCoreLength = 40 + (int)Pack.BE_To_UInt32(enc, pos + 36);
                composer.Bytes(enc, pos, keyCoreLength);
                int cacheCount = (int)Pack.BE_To_UInt32(enc, pos + keyCoreLength);
                pos += keyCoreLength + 4 + cacheCount * m; // skip the version 1 tree-cache field
            }
            composer.Bytes(enc, pos, enc.Length - pos); // the chaining signatures

            HssPrivateKeyParameters decoded = HssPrivateKeyParameters.GetInstance(composer.Build());

            Assert.AreEqual(generated.Level, decoded.Level);
            Assert.AreEqual(generated.GetIndex(), decoded.GetIndex());
            Assert.AreEqual(generated.IndexLimit, decoded.IndexLimit);

            HssSignature signature = LmsTestUtilities.GenerateHssSignature(decoded, Hex.Decode("ABCDEF"));
            Assert.True(LmsTestUtilities.VerifyHssSignature(generated.GetPublicKey(), signature, Hex.Decode("ABCDEF")));
        }

        /**
         * The current encoding is version 1: the component keys always carry the tree-cache field, and the
         * version - the first four bytes - is what a pre-cache release's decoder rejects cleanly instead of
         * misparsing the cache as key material.
         */
        [Test]
        public void Version1HssKeyRoundTrip()
        {
            HssPrivateKeyParameters generated = GenerateKey(2);

            byte[] enc = generated.GetEncoded();

            Assert.AreEqual(1U, Pack.BE_To_UInt32(enc, 0), "encoding version");

            HssPrivateKeyParameters decoded = HssPrivateKeyParameters.GetInstance(enc);

            Assert.True(decoded.Equals(generated));

            HssSignature signature = LmsTestUtilities.GenerateHssSignature(decoded, Hex.Decode("ABCDEF"));
            Assert.True(LmsTestUtilities.VerifyHssSignature(generated.GetPublicKey(), signature, Hex.Decode("ABCDEF")));
        }

        /**
         * The level count d and the index pair are range checked at decode. Before bc-java github #2414 only
         * the version was guarded, so d = 0 decoded and the empty key list then threw an unchecked exception
         * out of the signing call rather than being refused as a bad key.
         */
        [Test]
        public void PrivateKeyLevelCountRangeChecked()
        {
            HssPrivateKeyParameters key = GenHssKey();
            byte[] enc = key.GetEncoded();

            // d sits at offset 4, after the version
            int[] badD = { 0, -1, 9, int.MinValue, int.MaxValue };
            for (int i = 0; i != badD.Length; i++)
            {
                byte[] corrupt = Arrays.Clone(enc);
                Pack.UInt32_To_BE((uint)badD[i], corrupt, 4);
                var ex = Assert.Throws<IOException>(
                    () => HssPrivateKeyParameters.GetInstance(corrupt), "no exception on d = " + badD[i]);
                Assert.True(ex.Message.StartsWith("d value of HSS private key out of range"));
            }

            // index at offset 8, maxIndex at 16, both u64
            long[][] badIndex = { new long[]{ -1L, 1024L }, new long[]{ 0L, -1L }, new long[]{ 100L, 10L } };
            for (int i = 0; i != badIndex.Length; i++)
            {
                byte[] corrupt = Arrays.Clone(enc);
                Pack.UInt64_To_BE((ulong)badIndex[i][0], corrupt, 8);
                Pack.UInt64_To_BE((ulong)badIndex[i][1], corrupt, 16);
                var ex = Assert.Throws<IOException>(
                    () => HssPrivateKeyParameters.GetInstance(corrupt),
                    "no exception on index = " + badIndex[i][0] + " maxIndex = " + badIndex[i][1]);
                Assert.True(ex.Message.StartsWith("HSS private key index out of range"));
            }

            // the genuine encoding still decodes and signs verifiably
            HssPrivateKeyParameters decoded = HssPrivateKeyParameters.GetInstance(enc);
            HssSignature signature = LmsTestUtilities.GenerateHssSignature(decoded, Hex.Decode("ABCDEF"));
            Assert.True(LmsTestUtilities.VerifyHssSignature(key.GetPublicKey(), signature, Hex.Decode("ABCDEF")));
        }

        /**
         * GetInstance(privEnc, pubEnc) cross-checks the root against the public key it is handed, which
         * catches a tree cache that is self-consistent but belongs to a different key (bc-java github #2414).
         */
        [Test]
        public void PrivateKeyCheckedAgainstSuppliedPublicKey()
        {
            HssPrivateKeyParameters keyA = GenHssKey();
            HssPrivateKeyParameters keyB = GenHssKey();

            byte[] privA = keyA.GetEncoded();
            byte[] pubA = keyA.GetPublicKey().GetEncoded();
            byte[] pubB = keyB.GetPublicKey().GetEncoded();

            // matching pair: accepted, and the public key reported agrees
            HssPrivateKeyParameters decoded = HssPrivateKeyParameters.GetInstance(privA, pubA);
            Assert.True(Arrays.AreEqual(pubA, decoded.GetPublicKey().GetEncoded()));

            // another key's public key: refused on its identifier before the cached root is consulted
            var ex = Assert.Throws<IOException>(
                () => HssPrivateKeyParameters.GetInstance(privA, pubB));
            Assert.True(ex.Message.StartsWith("HSS public key does not match"));

            // the right key at the wrong level: refused
            LmsPublicKeyParameters lmsPubA = keyA.GetPublicKey().LmsPublicKey;
            byte[] pubAWrongLevel = new HssPublicKeyParameters(keyA.Level + 1, lmsPubA).GetEncoded();
            ex = Assert.Throws<IOException>(
                () => HssPrivateKeyParameters.GetInstance(privA, pubAWrongLevel));
            Assert.True(ex.Message.StartsWith("HSS public key does not match"));

            // the right identifier and parameters with a different root: the cached root catches it
            byte[] wrongT1 = lmsPubA.GetT1();
            wrongT1[0] ^= 1;
            byte[] pubAWrongRoot = new HssPublicKeyParameters(keyA.Level, new LmsPublicKeyParameters(
                lmsPubA.GetSigParameters(), lmsPubA.GetOtsParameters(), wrongT1, lmsPubA.GetI())).GetEncoded();
            ex = Assert.Throws<IOException>(
                () => HssPrivateKeyParameters.GetInstance(privA, pubAWrongRoot));
            Assert.True(ex.Message.StartsWith("HSS private key tree cache does not match"));
        }

        private static HssPrivateKeyParameters GenerateKey(int d)
        {
            LmsParameters[] lmsParameters = new LmsParameters[d];
            for (int t = 0; t < d; t++)
            {
                lmsParameters[t] = LmsParameters.Create(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4);
            }

            return LmsTestUtilities.GenerateHssPrivateKey(new HssKeyGenerationParameters(lmsParameters, new SecureRandom()));
        }

        /**
         * Test Case 1 Signature
         * From https://tools.ietf.org/html/rfc8554#appendix-F
         */
        [Test]
        public void HssVector_1()
        {
            var blocks = LoadTestResource("pqc/crypto/lms/testcase_1.txt");

            HssPublicKeyParameters publicKey = HssPublicKeyParameters.GetInstance(blocks[0]);
            byte[] message = blocks[1];
            byte[] signature = blocks[2];
            Assert.True(Verify(publicKey, signature, message), "Test Case 1");
        }

        /**
         * Test Case 1 Signature
         * From https://tools.ietf.org/html/rfc8554#appendix-F
         */
        [Test]
        public void HssVector_2()
        {
            var blocks = LoadTestResource("pqc/crypto/lms/testcase_2.txt");

            HssPublicKeyParameters publicKey = HssPublicKeyParameters.GetInstance(blocks[0]);
            byte[] message = blocks[1];
            byte[] signature = blocks[2];
            Assert.True(Verify(publicKey, signature, message), "Test Case 2 Signature");

            LmsPublicKeyParameters lmsPub = LmsPublicKeyParameters.GetInstance(blocks[3]);
            Assert.True(VerifyLms(lmsPub, blocks[4], message), "Test Case 2 Signature 2");
        }

        private static IEnumerable<TestCaseData> Rfc9858Vectors()
        {
            yield return new TestCaseData("rfc9858_testcase_1.txt", LMSigParameters.lms_sha256_n24_h5,
                LMOtsParameters.sha256_n24_w8, true)
                .SetArgDisplayNames("A.1", "LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W8", "regenerate");

            yield return new TestCaseData("rfc9858_testcase_2.txt", LMSigParameters.lms_shake256_n24_h5,
                LMOtsParameters.shake256_n24_w8, true)
                .SetArgDisplayNames("A.2", "LMS_SHAKE_N24_H5", "LMOTS_SHAKE_N24_W8", "regenerate");

            // The RFC's A.3 section title says SHA-256/256, but its parameter sets and message are SHAKE256/256.
            yield return new TestCaseData("rfc9858_testcase_3.txt", LMSigParameters.lms_shake256_n32_h5,
                LMOtsParameters.shake256_n32_w8, true)
                .SetArgDisplayNames("A.3", "LMS_SHAKE_N32_H5", "LMOTS_SHAKE_N32_W8", "regenerate");

            // Verification only: regenerating the key means building a 2^20-leaf tree, far too slow for a
            // unit test.
            yield return new TestCaseData("rfc9858_testcase_4.txt", LMSigParameters.lms_sha256_n24_h20,
                LMOtsParameters.sha256_n24_w4, false)
                .SetArgDisplayNames("A.4", "LMS_SHA256_M24_H20", "LMOTS_SHA256_N24_W4", "verify only");
        }

        /**
         * RFC 9858 Appendix A: https://www.rfc-editor.org/rfc/rfc9858#appendix-A. Each vector is a single-level
         * HSS key with its private SEED and I, a message and a signature, all produced with the RFC 8554
         * Appendix A key derivation. These are the only known-answer vectors covering the truncated (n=24) and
         * SHAKE parameter sets, so they pin the digest handling that the n=32 SHA-256 vectors cannot reach.
         *
         * Three things are checked: the RFC signature verifies under the RFC public key; the key regenerated
         * from SEED and I reproduces the RFC public key; and signing the message at the signature's q
         * reproduces the RFC signature byte for byte.
         */
        [TestCaseSource(nameof(Rfc9858Vectors))]
        public void Rfc9858Vector(string vector, LMSigParameters sigParams, LMOtsParameters otsParams,
            bool regenerate)
        {
            var blocks = LoadTestResource("pqc/crypto/lms/" + vector);

            byte[] seed = blocks[0];
            byte[] I = blocks[1];
            HssPublicKeyParameters publicKey = HssPublicKeyParameters.GetInstance(blocks[2]);
            byte[] message = blocks[3];
            byte[] signature = blocks[4];

            Assert.AreEqual(1, publicKey.Level, "levels");

            LmsPublicKeyParameters lmsPub = publicKey.LmsPublicKey;
            Assert.AreEqual(sigParams, lmsPub.GetSigParameters(), "LMS type");
            Assert.AreEqual(otsParams, lmsPub.GetOtsParameters(), "LM-OTS type");
            Assert.True(Arrays.AreEqual(I, lmsPub.GetI()), "I");
            Assert.AreEqual(sigParams.M, seed.Length, "SEED length");

            Assert.True(Verify(publicKey, signature, message), "RFC signature verifies");

            // Nspk is 0, so the HSS signature is u32str(0) followed by the LMS signature, which opens with q.
            Assert.AreEqual(0U, Pack.BE_To_UInt32(signature, 0), "Nspk");
            byte[] lmsSignature = Arrays.CopyOfRange(signature, 4, signature.Length);
            Assert.True(VerifyLms(lmsPub, lmsSignature, message), "RFC LMS signature verifies");

            if (!regenerate)
                return;

            int q = (int)Pack.BE_To_UInt32(lmsSignature, 0);
            LmsPrivateKeyParameters privateKey = LmsKey(sigParams, otsParams, q, I, seed);
            Assert.True(Arrays.AreEqual(lmsPub.GetEncoded(), privateKey.GetPublicKey().GetEncoded()),
                "public key from SEED and I");

            LmsSigner signer = new LmsSigner();
            signer.Init(true, privateKey);
            Assert.True(Arrays.AreEqual(lmsSignature, signer.GenerateSignature(message)),
                "signature at q from SEED and I");
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
                        blocks.Add(LmsTestUtilities.ExtractPrefixedBytes(sw.ToString()));
                        sw.Length = 0;
                    }
                }
                sw.Append(line);
                sw.Append("\n");
            }

            if (sw.Length > 0)
            {
                blocks.Add(LmsTestUtilities.ExtractPrefixedBytes(sw.ToString()));
                sw.Length = 0;
            }
            return blocks;
        }

        /**
         * Test the generation of public keys from private key SEED and I.
         * Level 0
         */
        [Test]
        public void GenPublicKeys_L0()
        {
            byte[] seed = Hex.Decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
            int level = 0;
            LmsPrivateKeyParameters lmsPrivateKey = LmsKey(LMSigParameters.GetParametersByID(6),
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
        public void GenPublicKeys_L1()
        {
            byte[] seed = Hex.Decode("a1c4696e2608035a886100d05cd99945eb3370731884a8235e2fb3d4d71f2547");
            int level = 1;
            LmsPrivateKeyParameters lmsPrivateKey = LmsKey(LMSigParameters.GetParametersByID(5),
                LMOtsParameters.GetParametersByID(4), level, Hex.Decode("215f83b7ccb9acbcd08db97b0d04dc2b"), seed);
            LmsPublicKeyParameters publicKey = lmsPrivateKey.GetPublicKey();
            Assert.True(Arrays.AreEqual(publicKey.GetT1(),
                Hex.Decode("a1cd035833e0e90059603f26e07ad2aad152338e7a5e5984bcd5f7bb4eba40b7")));
            Assert.True(Arrays.AreEqual(publicKey.GetI(), Hex.Decode("215f83b7ccb9acbcd08db97b0d04dc2b")));
        }

        [Test]
        public void Generate()
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

            HssPrivateKeyParameters keyPair = LmsTestUtilities.GenerateHssPrivateKey(
                new HssKeyGenerationParameters(new LmsParameters[]
                {
                    LmsParameters.Create(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                    LmsParameters.Create(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w2),
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
            // Generate, hopefully the same HSSKeyPair for the same entropy.
            // This is a sanity test
            //
            {
                FixedSecureRandom.Source[] source1 = { new FixedSecureRandom.Source(fixedSource) };
                SecureRandom rand1 = new FixedSecureRandom(source1);

                HssPrivateKeyParameters regenKeyPair = LmsTestUtilities.GenerateHssPrivateKey(
                    new HssKeyGenerationParameters(new LmsParameters[]
                    {
                        LmsParameters.Create(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                        LmsParameters.Create(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w2),
                    }, rand1));

                Assert.True(
                    Arrays.AreEqual(regenKeyPair.GetPublicKey().GetEncoded(), keyPair.GetPublicKey().GetEncoded()),
                    "Both generated keys are the same");

                var keyPairKeys = keyPair.GetKeys();
                var regenKeyPairKeys = regenKeyPair.GetKeys();

                Assert.AreEqual(keyPairKeys.Count, regenKeyPairKeys.Count, "same private key size");

                for (int t = 0; t < keyPairKeys.Count; t++)
                {
                    //
                    // Check the private keys can be encoded and are the same.
                    //
                    byte[] pk1 = keyPairKeys[t].GetEncoded();
                    byte[] pk2 = regenKeyPairKeys[t].GetEncoded();
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

                HssPrivateKeyParameters differentKey = LmsTestUtilities.GenerateHssPrivateKey(
                    new HssKeyGenerationParameters(new LmsParameters[]
                    {
                        LmsParameters.Create(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                        LmsParameters.Create(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w2),
                    }, rand1)
                );

                Assert.False(
                    Arrays.AreEqual(differentKey.GetPublicKey().GetEncoded(), keyPair.GetPublicKey().GetEncoded()),
                    "Both generated keys are not the same");

                var keyPairKeys = keyPair.GetKeys();
                var differentKeyKeys = differentKey.GetKeys();

                for (int t = 0; t < keyPairKeys.Count; t++)
                {
                    //
                    // Check the private keys can be encoded and are not the same.
                    //
                    byte[] pk1 = keyPairKeys[t].GetEncoded();
                    byte[] pk2 = differentKeyKeys[t].GetEncoded();
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
        public void VectorsFromReference()
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
                        lmsParams.Add(LmsParameters.Create(lmsParameters[i], lmOtsParameters[i]));
                    }

                    //
                    // Using our fixed entropy source generate hss keypair
                    //

                    LmsParameters[] lmsParamsArray = new LmsParameters[lmsParams.Count];
                    lmsParams.CopyTo(lmsParamsArray, 0);
                    HssPrivateKeyParameters keyPair = LmsTestUtilities.GenerateHssPrivateKey(
                        new HssKeyGenerationParameters(lmsParamsArray, fixRnd)
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
                    HssSignature sig = LmsTestUtilities.GenerateHssSignature(keyPair, message);

                    HssSignature signatureFromVector = null;
                    if (!Arrays.AreEqual(sig.GetEncoded(), encodedSigFromVector))
                    {
                        signatureFromVector = HssSignature.GetInstance(encodedSigFromVector, d);
                        signatureFromVector.Equals(sig);
                    }

                    // check encoding signature matches.
                    Assert.True(Arrays.AreEqual(sig.GetEncoded(), encodedSigFromVector));

                    // Check we can verify our generated signature with the vectors sourced public key.
                    Assert.True(LmsTestUtilities.VerifyHssSignature(vectorSourcedPubKey, sig, message));

                    // Deserialize the signature from the vector.
                    signatureFromVector = HssSignature.GetInstance(encodedSigFromVector, d);

                    // Can we verify signature from vector with public key from vector.
                    Assert.True(LmsTestUtilities.VerifyHssSignature(vectorSourcedPubKey, signatureFromVector, message));

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
        public void VectorsFromReference_Expanded()
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
                    lmsParams.Add(LmsParameters.Create(lmsParameters[i], lmOtsParameters[i]));
                }

                LmsParameters[] lmsParamsArray = new LmsParameters[lmsParams.Count];
                lmsParams.CopyTo(lmsParamsArray, 0);
                HssPrivateKeyParameters keyPair = LmsTestUtilities.GenerateHssPrivateKey(
                    new HssKeyGenerationParameters(lmsParamsArray, fixRnd)
                );

                Assert.True(Arrays.AreEqual(hssPubEnc, keyPair.GetPublicKey().GetEncoded()));

                HssPublicKeyParameters pubKeyFromVector = HssPublicKeyParameters.GetInstance(hssPubEnc);
                HssPublicKeyParameters pubKeyGenerated = null;


                Assert.AreEqual(1024, keyPair.GetUsagesRemaining());
                Assert.AreEqual(1024, keyPair.IndexLimit);
                Assert.AreEqual(0, keyPair.GetIndex());

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
                            pair.IncrementIndex();
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
                        HssSignature sigCalculated = LmsTestUtilities.GenerateHssSignature(pair, message);
                        Assert.True(Arrays.AreEqual(sigCalculated.GetEncoded(), sigVectors[c]));

                        Assert.True(LmsTestUtilities.VerifyHssSignature(pubKeyFromVector, sigCalculated, message));
                        Assert.True(LmsTestUtilities.VerifyHssSignature(pubKeyGenerated, sigCalculated, message));

                        HssSignature sigFromVector = HssSignature.GetInstance(sigVectors[c],
                            pubKeyFromVector.Level);

                        Assert.True(LmsTestUtilities.VerifyHssSignature(pubKeyFromVector, sigFromVector, message));
                        Assert.True(LmsTestUtilities.VerifyHssSignature(pubKeyGenerated, sigFromVector, message));


                        Assert.True(sigCalculated.Equals(sigFromVector));


                        c++;
                    }
                    else
                    {
                        pair.IncrementIndex();
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
        public void Remaining()
        {
            HssPrivateKeyParameters keyPair = LmsTestUtilities.GenerateHssPrivateKey(
                new HssKeyGenerationParameters(new LmsParameters[]
                {
                    LmsParameters.Create(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w2),
                    LmsParameters.Create(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w2),
                },
                new SecureRandom())
            );


            LmsPrivateKeyParameters lmsKey = keyPair.GetKey(keyPair.L - 1);
            //
            // There should be a max of 32768 signatures for this key.
            //
            Assert.True(1024 == keyPair.GetUsagesRemaining());

            keyPair.IncrementIndex();
            keyPair.IncrementIndex();
            keyPair.IncrementIndex();
            keyPair.IncrementIndex();
            keyPair.IncrementIndex();

            Assert.True(5 == keyPair.GetIndex()); // Next key is at index 5!

            Assert.True(1024 - 5 == keyPair.GetUsagesRemaining());

            HssPrivateKeyParameters shard = keyPair.ExtractKeyShard(10);

            Assert.True(10 == shard.GetUsagesRemaining());
            Assert.True(15 == shard.IndexLimit);
            Assert.True(5 == shard.GetIndex());

            // Should not be the same.
            Assert.False(shard.GetIndex() == keyPair.GetIndex());

            //
            // Should be 17 left, it will throw if it has been exhausted.
            //
            for (int t = 0; t < 17; t++)
            {
                keyPair.IncrementIndex();
            }

            // We have used 32 keys.
            Assert.True(1024 - 32 == keyPair.GetUsagesRemaining());

            LmsTestUtilities.GenerateHssSignature(keyPair, Encoding.ASCII.GetBytes("Foo"));

            //
            // This should trigger the generation of a new key.
            //
            LmsPrivateKeyParameters potentialNewLMSKey = keyPair.GetKey(keyPair.L - 1);
            Assert.False(potentialNewLMSKey.Equals(lmsKey));
        }

        [Test]
        public void Sharding()
        {
            HssPrivateKeyParameters keyPair = LmsTestUtilities.GenerateHssPrivateKey(
                new HssKeyGenerationParameters(new LmsParameters[]
                {
                    LmsParameters.Create(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w2),
                    LmsParameters.Create(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w2),
                },
                new SecureRandom())
            );

            Assert.True(1024 == keyPair.GetUsagesRemaining());
            Assert.True(1024 == keyPair.IndexLimit);
            Assert.True(0 == keyPair.GetIndex());
            Assert.False(keyPair.IsShard());
            keyPair.IncrementIndex();


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
                shard.IncrementIndex();
            }

            HssSignature sig = LmsTestUtilities.GenerateHssSignature(shard, Encoding.ASCII.GetBytes("Cats"));

            //
            // Test it validates and nothing has gone wrong with the public keys.
            //
            Assert.True(LmsTestUtilities.VerifyHssSignature(keyPair.GetPublicKey(), sig,
                Encoding.ASCII.GetBytes("Cats")));
            Assert.True(LmsTestUtilities.VerifyHssSignature(shard.GetPublicKey(), sig,
                Encoding.ASCII.GetBytes("Cats")));

            // Signing again should Assert.Fail.

            try
            {
                LmsTestUtilities.GenerateHssSignature(shard, Encoding.ASCII.GetBytes("Cats"));
                Assert.Fail();
            }
            catch (Exception ex)
            {
                Assert.True(ex.Message.Equals("hss private key shard is exhausted"));
            }

            // Should work without throwing.
            LmsTestUtilities.GenerateHssSignature(keyPair, Encoding.ASCII.GetBytes("Cats"));
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
        public void SignUnitExhaustion()
        {
            HSSSecureRandom rand = new HSSSecureRandom();

            HssPrivateKeyParameters keyPair = LmsTestUtilities.GenerateHssPrivateKey(
                new HssKeyGenerationParameters(new LmsParameters[]
                {
                    LmsParameters.Create(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w2),
                    LmsParameters.Create(LMSigParameters.lms_sha256_n32_h10, LMOtsParameters.sha256_n32_w1),
                }, rand)
            );

            HssPublicKeyParameters pk = keyPair.GetPublicKey();


            int ctr = 0;
            byte[] message = new byte[32];

            //
            // There should be a max of 32768 signatures for this key.
            //

            Assert.AreEqual(32768L, keyPair.GetUsagesRemaining());

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
                        Pack.UInt32_To_BE((uint)ctr, message, 0);
                        byte[] sig = Sign(keyPair, message);

                        var keyPairKeys = keyPair.GetKeys();

                        Assert.AreEqual(ctr % 1024, LeafSignatureQ(keyPair, sig));

                        // Check there was a post increment in the tail end LMS key.
                        Assert.AreEqual(ctr % 1024 + 1, keyPairKeys[keyPair.Level - 1].GetIndex(), "" + ctr);

                        Assert.AreEqual(ctr + 1, keyPair.GetIndex());

                        // Validate the heirarchial path building was correct.

                        long[] qValues = new long[keyPairKeys.Count];
                        long q = ctr;

                        for (int t = keyPairKeys.Count - 1; t >= 0; t--)
                        {
                            LMSigParameters sigParameters = keyPairKeys[t].SigParameters;
                            int mask = (1 << sigParameters.H) - 1;
                            qValues[t] = q & mask;
                            q >>= sigParameters.H;
                        }

                        for (int t = 0; t < keyPairKeys.Count; t++)
                        {
                            Assert.AreEqual(keyPairKeys[t].GetIndex() - 1, qValues[t], "" + ctr);
                        }

                        Assert.True(Verify(pk, sig, message));
                        Assert.AreEqual(LMSigParameters.lms_sha256_n32_h10.ID, LeafSignatureType(keyPair, sig));

                        {
                            //
                            // Vandalise hss signature.
                            //
                            byte[] rawSig = sig;
                            rawSig[100] ^= 1;
                            byte[] parsedSig = rawSig;
                            Assert.False(Verify(pk, parsedSig, message));

                            try
                            {
                                // a key claiming one more level than the signature carries
                                new HssPublicKeyParameters(pk.Level + 1, pk.LmsPublicKey).GenerateLmsContext(rawSig);
                                Assert.Fail();
                            }
                            catch (InvalidOperationException ex)
                            {
                                Assert.That(ex.Message.Contains("nspk exceeded maxNspk"));
                            }
                        }

                        {
                            //
                            // Vandalise hss message
                            //
                            byte[] newMsg = Arrays.Clone(message);
                            newMsg[1] ^= 1;
                            Assert.False(Verify(pk, sig, newMsg));
                        }

                        {
                            //
                            // Vandalise public key
                            //
                            byte[] pkEnc = pk.GetEncoded();
                            pkEnc[35] ^= 1;
                            HssPublicKeyParameters rebuiltPk = HssPublicKeyParameters.GetInstance(pkEnc);
                            Assert.False(Verify(rebuiltPk, sig, message));
                        }
                    }
                    else
                    {
                        // Skip some keys.
                        keyPair.IncrementIndex();
                    }

                    ctr++;
                }

                Assert.Fail();
            }
            catch (ExhaustedPrivateKeyException ex)
            {
                Assert.True(keyPair.GetUsagesRemaining() == 0);
                Assert.True(ctr == 32768);
                Assert.True(ex.Message.Contains("hss private key is exhausted"));
            }
        }

        [Test]
        public void IndexRollbackRejected()
        {
            HssPrivateKeyParameters key = GenHssKey();
            HssSigner signer = new HssSigner();
            signer.Init(true, key);
            for (int i = 0; i != 5; i++)
            {
                signer.GenerateSignature(Hex.Decode("48656c6c6f"));
            }

            byte[] enc = key.GetEncoded();
            Assert.AreEqual(5UL, Pack.BE_To_UInt64(enc, 8));

            // roll the declared index back, leaving the component keys advanced
            for (int roll = 0; roll != 5; roll++)
            {
                byte[] rolled = Arrays.Clone(enc);
                Pack.UInt64_To_BE((ulong)roll, rolled, 8);
                try
                {
                    HssPrivateKeyParameters.GetInstance(rolled);
                    Assert.Fail("no exception on index rolled back to " + roll);
                }
                catch (IOException e)
                {
                    Assert.That(e.Message.StartsWith($"HSS private key index {roll} does not match the component key indices"),
                        e.Message);
                }
            }

            // and the other direction: roll a component key's q back, leaving the declared index alone
            int secretLen = (int)Pack.BE_To_UInt32(enc, 25 + 28 + 8);
            int cacheCount = (int)Pack.BE_To_UInt32(enc, 25 + 40 + secretLen);
            int m = LMSigParameters.lms_sha256_n32_h5.M;
            int componentSize = 4 + 4 + 4 + 16 + 4 + 4 + 4 + secretLen + 4 + cacheCount * m;
            int lastQOff = 25 + componentSize + 28;
            Assert.True(Pack.BE_To_UInt32(enc, lastQOff) > 0U, "component q should be advanced");

            byte[] qRolled = Arrays.Clone(enc);
            Pack.UInt32_To_BE(0U, qRolled, lastQOff);
            try
            {
                HssPrivateKeyParameters.GetInstance(qRolled);
                Assert.Fail("no exception on component key q rolled back");
            }
            catch (IOException e)
            {
                Assert.True(e.Message.StartsWith("HSS private key index"), e.Message);
            }

            // the untouched encoding still decodes and signs verifiably
            HssPrivateKeyParameters decoded = HssPrivateKeyParameters.GetInstance(enc);
            Assert.AreEqual(5L, decoded.GetIndex());
            byte[] msg = Hex.Decode("48656c6c6f");
            Assert.True(Verify(key.GetPublicKey(), Sign(decoded, msg), msg));
        }

        /// <sumamry>
        /// Encode and decode across a subtree boundary, and round-trip a shard - the compatibility half of
        /// <see cref="IndexRollbackRejected"/>. A level above the last carries a q that has already advanced past the
        /// subtree it signed, so the identity the check applies has to account for that; walking across the boundary
        /// where the lower tree is replaced is what proves it does.
        /// </sumamry>
        [Test]
        public void IndexRoundTripsAcrossSubtreeBoundary()
        {
            HssPrivateKeyParameters key = GenHssKey();
            HssPublicKeyParameters pub = key.GetPublicKey();
            HssSigner signer = new HssSigner();
            byte[] msg = Hex.Decode("48656c6c6f");

            // 2^5 = 32 signatures per tree, so 40 crosses the boundary and rebuilds the lower tree
            for (int i = 0; i != 40; i++)
            {
                HssPrivateKeyParameters decoded = HssPrivateKeyParameters.GetInstance(key.GetEncoded());
                Assert.AreEqual(key.GetIndex(), decoded.GetIndex());
                Assert.True(Verify(pub, Sign(decoded, msg), msg), "index " + key.GetIndex());

                signer.Init(true, key);
                signer.GenerateSignature(msg);
            }

            HssPrivateKeyParameters shard = key.ExtractKeyShard(4);
            HssPrivateKeyParameters decodedShard = HssPrivateKeyParameters.GetInstance(shard.GetEncoded());
            Assert.AreEqual(shard.GetIndex(), decodedShard.GetIndex());
        }

        private static HssPrivateKeyParameters GenHssKey()
        {
            HssKeyPairGenerator gen = new HssKeyPairGenerator();
            gen.Init(new HssKeyGenerationParameters(new LmsParameters[]{
                LmsParameters.Create(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1),
                LmsParameters.Create(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1) },
                new SecureRandom()));
            return (HssPrivateKeyParameters)gen.GenerateKeyPair().Private;
        }

        private static byte[] Sign(HssPrivateKeyParameters key, byte[] message)
        {
            HssSigner signer = new HssSigner();
            signer.Init(true, key);
            return signer.GenerateSignature(message);
        }

        private static bool Verify(HssPublicKeyParameters key, byte[] signature, byte[] message)
        {
            HssSigner signer = new HssSigner();
            signer.Init(false, key);
            return signer.VerifySignature(message, signature);
        }

        private static bool VerifyLms(LmsPublicKeyParameters key, byte[] signature, byte[] message)
        {
            LmsSigner signer = new LmsSigner();
            signer.Init(false, key);
            return signer.VerifySignature(message, signature);
        }

        private static LmsPrivateKeyParameters LmsKey(LMSigParameters sigParams, LMOtsParameters otsParams, int q,
            byte[] I, byte[] seed)
        {
            return new LmsPrivateKeyParameters(sigParams, otsParams, q, I, 1 << sigParams.H, seed);
        }

        // The leaf tree's LMS signature is the tail of an HSS signature (RFC 8554 sec. 6.1); its
        // length follows from the leaf key's parameters (sec. 5.4): u32str(q) || ots_signature ||
        // u32str(type) || path, where ots_signature is u32str(otstype) || C || y (sec. 4.5).
        private static int LeafSignatureOffset(HssPrivateKeyParameters key, byte[] hssSignature)
        {
            LmsPrivateKeyParameters leaf = key.GetKeys()[key.Level - 1];
            int n = leaf.OtsParameters.N;
            int p = leaf.OtsParameters.P;
            int h = leaf.SigParameters.H;
            int m = leaf.SigParameters.M;

            return hssSignature.Length - (4 + (4 + n + p * n) + 4 + h * m);
        }

        private static int LeafSignatureQ(HssPrivateKeyParameters key, byte[] hssSignature) =>
            (int)Pack.BE_To_UInt32(hssSignature, LeafSignatureOffset(key, hssSignature));

        private static int LeafSignatureType(HssPrivateKeyParameters key, byte[] hssSignature)
        {
            LmsPrivateKeyParameters leaf = key.GetKeys()[key.Level - 1];
            int h = leaf.SigParameters.H;
            int m = leaf.SigParameters.M;

            return (int)Pack.BE_To_UInt32(hssSignature, hssSignature.Length - h * m - 4);
        }

        /// <summary>
        /// The lower half of a hierarchy repositions within its own tree - identifier and seed unchanged, only q moves
        /// - so ResetKeyToIndex must share the tree the component key already has rather than regenerate one identical
        /// to it.
        /// </summary>
        [Test]
        public void BottomLevelRepositionKeepsTheTree()
        {
            LMSigParameters sigParams = LMSigParameters.lms_sha256_n32_h5;
            LMOtsParameters otsParams = LMOtsParameters.sha256_n32_w2;

            HssKeyPairGenerator gen = new HssKeyPairGenerator();
            gen.Init(new HssKeyGenerationParameters(
                new LmsParameters[]{
                    LmsParameters.Create(sigParams, otsParams),
                    LmsParameters.Create(sigParams, otsParams),
                },
                new SecureRandom()));
            HssPrivateKeyParameters hss = (HssPrivateKeyParameters)gen.GenerateKeyPair().Private;

            HssPublicKeyParameters pubKey = hss.GetPublicKey();
            List<LmsPrivateKeyParameters> keys = new List<LmsPrivateKeyParameters>(hss.GetKeys());
            List<LmsSignature> sigs = new List<LmsSignature>(hss.GetSig());
            byte[] bottomT1 = keys[1].GetPublicKey().GetT1();

            // an index whose bottom level q moves while the root's does not: the branch where the
            // derived identifier and seed match and only the position is wrong
            HssPrivateKeyParameters moved = new HssPrivateKeyParameters(2, keys, sigs, 3, 1L << (2 * sigParams.H));

            Assert.AreSame(keys[0], moved.GetRootKey(), "the reset replaced the root key");
            Assert.AreNotSame(keys[1], moved.GetKey(1), "the reset failed to reposition the bottom key");
            Assert.AreEqual(3, moved.GetKey(1).GetIndex());
            Assert.NotNull(moved.GetKey(1).PeekRootT(), "repositioning discarded the tree cache");
            Assert.True(Arrays.AreEqual(bottomT1, moved.GetKey(1).GetPublicKey().GetT1()),
                "repositioning changed the bottom public key");
            Assert.AreSame(sigs[0], moved.GetSig()[0], "repositioning re-signed a public key that had not changed");
            Assert.True(Arrays.AreEqual(pubKey.GetEncoded(), moved.GetPublicKey().GetEncoded()),
                "repositioning changed the HSS public key");

            byte[] msg = Hex.Decode("6162636465");
            HssSigner signer = new HssSigner();
            signer.Init(true, moved);
            byte[] sig = signer.GenerateSignature(msg);

            HssSigner verifier = new HssSigner();
            verifier.Init(false, pubKey);
            Assert.True(verifier.VerifySignature(msg, sig),
                "repositioned key produced a signature that does not verify");
        }

        /// <summary>
        /// Wrapping an LMS key as a single level HSS key keeps the key it was given, rather than regenerating it.
        /// ResetKeyToIndex compares each level's q against the value derived from the HSS index, and an intermediate
        /// level reads one past that value because it has already post incremented past the leaf it signed - but the
        /// last level reads the derived value itself, and when the hierarchy has one level the root is the last level.
        /// Applying the intermediate rule there made the comparison always fail, so every wrap rebuilt the whole
        /// Merkle tree, so the tree was built twice - once to get the public key, once here - and the node cache the
        /// first build filled was discarded with it.
        /// </summary>
        [Test]
        public void SingleLevelWrapKeepsTheKey()
        {
            LMSigParameters sigParams = LMSigParameters.lms_sha256_n32_h5;
            LMOtsParameters otsParams = LMOtsParameters.sha256_n32_w2;

            LmsKeyPairGenerator gen = new LmsKeyPairGenerator();
            gen.Init(new LmsKeyGenerationParameters(LmsParameters.Create(sigParams, otsParams), new SecureRandom()));
            LmsPrivateKeyParameters lms = (LmsPrivateKeyParameters)gen.GenerateKeyPair().Private;

            byte[] rootT1 = lms.GetPublicKey().GetT1();
            Assert.True(lms.IsTreeCachePrimed(), "expected the generator to leave the cache primed");

            HssPrivateKeyParameters wrapped = new HssPrivateKeyParameters(lms, lms.GetIndex(),
                lms.GetIndex() + lms.GetUsagesRemaining());

            Assert.AreSame(lms, wrapped.GetRootKey(), "the wrap regenerated the root key");
            Assert.True(wrapped.GetRootKey().IsTreeCachePrimed(), "the wrap discarded the tree cache");
            Assert.That(Arrays.AreEqual(rootT1, wrapped.GetPublicKey().LmsPublicKey.GetT1()),
                "the wrap changed the public key");

            // and again from a position part way through the key
            LmsSigner lmsSigner = new LmsSigner();
            lmsSigner.Init(true, lms);
            for (int i = 0; i != 3; i++)
            {
                lmsSigner.GenerateSignature(Hex.Decode("48656c6c6f"));
            }
            Assert.AreEqual(3, lms.GetIndex());

            HssPrivateKeyParameters advanced = new HssPrivateKeyParameters(lms, lms.GetIndex(),
                lms.GetIndex() + lms.GetUsagesRemaining());

            Assert.AreSame(lms, advanced.GetRootKey(), "the wrap regenerated an advanced root key");
            Assert.AreEqual(3, advanced.GetIndex(), "the wrap moved the index");

            // the reset itself still works: asked for a different (later - see ResetKeyToIndexRefusesToRewind)
            // position, it does reposition
            HssPrivateKeyParameters moved = new HssPrivateKeyParameters(lms, 4, 1 << sigParams.H);

            Assert.AreNotSame(lms, moved.GetRootKey(), "the reset failed to reposition to a different index");
            Assert.AreEqual(4, moved.GetRootKey().GetIndex());

            // the Merkle tree is a function of I, the seed and the parameters and not of q, so the
            // repositioned key is entitled to the tree it was built from rather than a rebuild costing
            // about as much as generating the key. peekRootT is asked before getPublicKey below, which
            // would prime the cache itself and hide the difference.
            Assert.NotNull(moved.GetRootKey().PeekRootT(), "repositioning discarded the tree cache");
            Assert.AreEqual(1 << sigParams.H, moved.GetRootKey().IndexLimit,
                "repositioning narrowed the range of the key");

            Assert.That(Arrays.AreEqual(rootT1, moved.GetPublicKey().LmsPublicKey.GetT1()),
                "repositioning changed the public key");

            // a signature from the wrapped key still verifies under the original public key
            byte[] msg = Hex.Decode("6162636465");
            HssSigner signer = new HssSigner();
            signer.Init(true, advanced);
            byte[] sig = signer.GenerateSignature(msg);

            HssSigner verifier = new HssSigner();
            verifier.Init(false, advanced.GetPublicKey());
            Assert.True(verifier.VerifySignature(msg, sig), "wrapped key produced a signature that does not verify");
        }

        /*
         * The context-based signing API on the HSS key (ILmsContextBasedSigner: GenerateLmsContext, absorb the message,
         * GenerateSignature) is the path the promoted signers will drive, and nothing else exercised it: an off-by-one
         * in the level count passed to the encoder went unnoticed. Round-trip it at one and two levels, and pin the
         * Nspk field the encoding starts with.
         */
        [Test]
        public void ContextBasedSigningRoundTrip()
        {
            LmsParameters lms = LmsParameters.Create(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w2);
            byte[] msg = Hex.Decode("48656c6c6f");

            for (int level = 1; level <= 2; ++level)
            {
                LmsParameters[] levels = new LmsParameters[level];
                for (int i = 0; i < level; ++i)
                {
                    levels[i] = lms;
                }

                HssPrivateKeyParameters hss = LmsTestUtilities.GenerateHssPrivateKey(
                    new HssKeyGenerationParameters(levels, new SecureRandom()));
                HssPublicKeyParameters pub = hss.GetPublicKey();

                ILmsContextBasedSigner signer = hss;
                LmsContext context = signer.GenerateLmsContext();
                context.BlockUpdate(msg, 0, msg.Length);
                byte[] sig = signer.GenerateSignature(context);

                Assert.AreEqual(1, hss.GetIndex(), "level " + level);
                Assert.AreEqual((uint)(level - 1), Pack.BE_To_UInt32(sig, 0), "Nspk at level " + level);

                // verifies through the static API and through the signer
                Assert.True(LmsTestUtilities.VerifyHssSignature(pub, HssSignature.GetInstance(sig, level), msg),
                    "level " + level);

                HssSigner verifier = new HssSigner();
                verifier.Init(false, pub);
                Assert.True(verifier.VerifySignature(msg, sig), "level " + level);

                // and is byte for byte what the one-shot API produces for the next one-time key
                HssSigner oneShot = new HssSigner();
                oneShot.Init(true, hss);
                byte[] next = oneShot.GenerateSignature(msg);
                Assert.AreEqual(sig.Length, next.Length, "level " + level);
                Assert.AreEqual(2, hss.GetIndex(), "level " + level);
            }
        }

        /*
         * A component key whose identifier and seed are unchanged is the same tree; an index that would move it back
         * within that tree asks for one-time keys already used, and is refused. Forward moves still reposition.
         */
        [Test]
        public void ResetKeyToIndexRefusesToRewind()
        {
            LMSigParameters sigParams = LMSigParameters.lms_sha256_n32_h5;
            LMOtsParameters otsParams = LMOtsParameters.sha256_n32_w2;
            int twoToH = 1 << sigParams.H;
            byte[] msg = Hex.Decode("48656c6c6f");

            // single level: the root is the last level and reads its q directly
            LmsKeyPairGenerator gen = new LmsKeyPairGenerator();
            gen.Init(new LmsKeyGenerationParameters(LmsParameters.Create(sigParams, otsParams), new SecureRandom()));
            LmsPrivateKeyParameters lms = (LmsPrivateKeyParameters)gen.GenerateKeyPair().Private;
            for (int i = 0; i < 3; ++i)
            {
                LmsTestUtilities.GenerateSign(lms, msg);
            }
            Assert.AreEqual(3, lms.GetIndex());

            Assert.Throws<ArgumentException>(() => new HssPrivateKeyParameters(lms, 2, twoToH));
            Assert.AreEqual(3, new HssPrivateKeyParameters(lms, 3, twoToH).GetIndex());
            Assert.AreEqual(4, new HssPrivateKeyParameters(lms, 4, twoToH).GetKeys()[0].GetIndex());

            // two levels: the root is post-incremented past the child it signed, the bottom reads its q directly
            HssPrivateKeyParameters hss = LmsTestUtilities.GenerateHssPrivateKey(new HssKeyGenerationParameters(
                new LmsParameters[]
                {
                    LmsParameters.Create(sigParams, otsParams),
                    LmsParameters.Create(sigParams, otsParams),
                },
                new SecureRandom()));
            for (int i = 0; i < twoToH + 1; ++i)
            {
                LmsTestUtilities.GenerateHssSignature(hss, msg);
            }
            var keys = hss.GetKeys();
            var sig = hss.GetSig();
            long limit = (long)twoToH * twoToH;
            Assert.AreEqual(2, keys[0].GetIndex());
            Assert.AreEqual(1, keys[1].GetIndex());

            // back one leaf within the current bottom tree
            Assert.Throws<ArgumentException>(() => new HssPrivateKeyParameters(2, keys, sig, twoToH, limit));
            // back into the previous bottom tree, which the root has already signed and moved past
            Assert.Throws<ArgumentException>(() => new HssPrivateKeyParameters(2, keys, sig, 5, limit));
            // the position the keys are at, and one further on, are both fine
            Assert.AreEqual(twoToH + 1, new HssPrivateKeyParameters(2, keys, sig, twoToH + 1, limit).GetIndex());
            HssPrivateKeyParameters forward = new HssPrivateKeyParameters(2, keys, sig, twoToH + 8, limit);
            Assert.AreEqual(8, forward.GetKeys()[1].GetIndex());
            Assert.True(LmsTestUtilities.VerifyHssSignature(hss.GetPublicKey(),
                LmsTestUtilities.GenerateHssSignature(forward, msg), msg));
        }

        /*
         * An LmsSigner given a single-level HSS key used to sign with the root key directly, so the HSS index never
         * moved. ResetKeyToIndex - reached from ExtractKeyShard and the public constructor - then trusted the stale
         * index and moved the root back to one-time keys already used. Signing goes through the HSS key now, so the
         * two records of position advance together, and a shard taken afterwards starts where the signatures
         * stopped.
         */
        [Test]
        public void LmsSignerAdvancesSingleLevelHssIndex()
        {
            LMSigParameters sigParams = LMSigParameters.lms_sha256_n32_h5;
            LMOtsParameters otsParams = LMOtsParameters.sha256_n32_w2;

            HssPrivateKeyParameters hss = LmsTestUtilities.GenerateHssPrivateKey(new HssKeyGenerationParameters(
                new LmsParameters[]{ LmsParameters.Create(sigParams, otsParams) }, new SecureRandom()));
            HssPublicKeyParameters hssPub = hss.GetPublicKey();
            byte[] msg = Hex.Decode("48656c6c6f");

            LmsSigner lmsSigner = new LmsSigner();
            lmsSigner.Init(true, hss);

            LmsSigner hssVerifier = new LmsSigner();
            hssVerifier.Init(false, hssPub);

            for (int i = 0; i < 5; ++i)
            {
                byte[] sig = lmsSigner.GenerateSignature(msg);
                Assert.AreEqual(i, LmsSignature.GetInstance(sig).Q);
                Assert.AreEqual(i + 1, hss.GetIndex(), "LmsSigner left the HSS index behind");

                // an LMS signature, verifiable under either form of the public key
                Assert.True(VerifyLms(hssPub.LmsPublicKey, sig, msg));
                Assert.True(hssVerifier.VerifySignature(msg, sig));
            }

            // the LMS signature is the HSS one without its u32str(Nspk = 0) prefix (RFC 8554 sec. 6.1)
            HssSigner hssSigner = new HssSigner();
            hssSigner.Init(true, hss);
            byte[] hssSig = hssSigner.GenerateSignature(msg);
            Assert.AreEqual(0U, Pack.BE_To_UInt32(hssSig, 0));
            byte[] lmsPart = Arrays.CopyOfRange(hssSig, 4, hssSig.Length);
            Assert.AreEqual(5, LmsSignature.GetInstance(lmsPart).Q);
            Assert.True(VerifyLms(hssPub.LmsPublicKey, lmsPart, msg));

            // a shard taken now continues from the position the signatures reached
            HssPrivateKeyParameters shard = hss.ExtractKeyShard(3);
            Assert.AreEqual(6, shard.GetIndex());
            Assert.AreEqual(9, hss.GetIndex());
            Assert.AreEqual(6, LmsTestUtilities.GenerateHssSignature(shard, msg).Signature.Q);
            Assert.AreEqual(9, LmsTestUtilities.GenerateHssSignature(hss, msg).Signature.Q);
        }

        /*
         * The HSS index and the bottom key's one-time index are two records of one position and must be claimed
         * under the one monitor (bc-java github #2414). bc-java parks a signer inside the bottom key's claim with
         * a gated subclass; LmsPrivateKeyParameters is sealed here, so the two halves of the claim are separated
         * another way: a bottom key whose usage limit is below 2^h passes RangeTestKeys (which looks only at 2^h)
         * and is then refused by its own claim. Claimed bottom-key-first under the one monitor, that refusal
         * leaves the HSS index where it was; claimed in two steps, the HSS index is burned and the key encodes
         * to something its own decoder rejects. A contention sweep across a bottom-key rotation then checks that
         * every encoding taken while signatures are in flight decodes.
         */
        [Test]
        public void IndexAndComponentIndexClaimedTogether()
        {
            LMSigParameters sigParams = LMSigParameters.lms_sha256_n32_h5;
            LMOtsParameters otsParams = LMOtsParameters.sha256_n32_w2;
            int twoToH = 1 << sigParams.H;
            byte[] msg = Hex.Decode("48656c6c6f");

            byte[] I = Hex.Decode("000102030405060708090a0b0c0d0e0f");
            byte[] seed = Hex.Decode("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");

            LmsPrivateKeyParameters root = new LmsPrivateKeyParameters(sigParams, otsParams, 0, I, twoToH, seed);
            var child = root.DeriveChildKey();
            LmsPrivateKeyParameters bottom = new LmsPrivateKeyParameters(sigParams, otsParams, 0, child.Item1, 1,
                child.Item2);

            // the root signs the bottom key's public key, which advances the root's q to 1 - the position
            // ResetKeyToIndex expects of an intermediate level, so the key is kept as built
            LmsSignature chain = LmsTestUtilities.GenerateSign(root, bottom.GetPublicKey().ToByteArray());

            HssPrivateKeyParameters hss = new HssPrivateKeyParameters(2,
                new List<LmsPrivateKeyParameters> { root, bottom }, new List<LmsSignature> { chain }, 0,
                (long)twoToH * twoToH);

            Assert.AreSame(bottom, hss.GetKey(1), "the bottom key was regenerated, so its usage limit is gone");

            // the one signature the bottom key can give
            HssSignature first = LmsTestUtilities.GenerateHssSignature(hss, msg);
            Assert.True(LmsTestUtilities.VerifyHssSignature(hss.GetPublicKey(), first, msg));
            Assert.AreEqual(1, hss.GetIndex());

            // the next passes the range test but is refused by the bottom key's own claim
            Assert.Throws<ExhaustedPrivateKeyException>(() => LmsTestUtilities.GenerateHssSignature(hss, msg));
            Assert.AreEqual(1, hss.GetIndex(), "a refused claim moved the HSS index");
            Assert.AreEqual(1, hss.GetKey(1).GetIndex());

            // and the key still encodes to something its own decoder accepts
            HssPrivateKeyParameters decoded = HssPrivateKeyParameters.GetInstance(hss.GetEncoded());
            Assert.AreEqual(1, decoded.GetIndex());

            // contention sweep: signatures in flight, encodings taken and decoded throughout
            HssPrivateKeyParameters sweep = LmsTestUtilities.GenerateHssPrivateKey(new HssKeyGenerationParameters(
                new LmsParameters[]
                {
                    LmsParameters.Create(sigParams, otsParams),
                    LmsParameters.Create(sigParams, otsParams),
                },
                new SecureRandom()));
            HssPublicKeyParameters sweepPub = sweep.GetPublicKey();

            int count = twoToH + 8; // crosses one bottom-key rotation
            HssSignature[] signatures = new HssSignature[count];
            Exception signerFailure = null, encoderFailure = null;
            int snapshots = 0;

            Thread signer = new Thread(() =>
            {
                try
                {
                    HssSigner s = new HssSigner();
                    s.Init(true, sweep);
                    for (int i = 0; i < count; ++i)
                    {
                        signatures[i] = HssSignature.GetInstance(s.GenerateSignature(msg), 2);
                    }
                }
                catch (Exception e)
                {
                    signerFailure = e;
                }
            });

            Thread encoder = new Thread(() =>
            {
                try
                {
                    do
                    {
                        HssPrivateKeyParameters.GetInstance(sweep.GetEncoded());
                        ++snapshots;
                    }
                    while (signer.IsAlive);
                }
                catch (Exception e)
                {
                    encoderFailure = e;
                }
            });

            signer.Start();
            encoder.Start();
            signer.Join();
            encoder.Join();

            Assert.Null(signerFailure, "signing failed: " + signerFailure);
            Assert.Null(encoderFailure, "an encoding taken while a signature was in flight did not decode: "
                + encoderFailure);
            Assert.That(snapshots, Is.GreaterThan(0));
            Assert.AreEqual(count, sweep.GetIndex());

            var leavesUsed = new HashSet<string>();
            foreach (HssSignature signature in signatures)
            {
                Assert.True(LmsTestUtilities.VerifyHssSignature(sweepPub, signature, msg));

                LmsPublicKeyParameters bottomPub = signature.GetSignedPubKeys()[0].PublicKey;
                Assert.True(leavesUsed.Add(Hex.ToHexString(bottomPub.GetI()) + ":" + signature.Signature.Q),
                    "a one-time key was used twice");
            }
        }

        /*
         * More than one level of an HSS key can be exhausted at once: the bottom tree's last one-time key was also
         * the last the tree above it could sign for. Every exhausted level is then rebuilt, and the rebuild has to
         * reach readers as one hierarchy. GetKeys/GetSig take no monitor, so a rebuild published a level at a time
         * shows a hierarchy in which the fresh tree at level i sits above the signature the tree it replaced made
         * over the still-exhausted level i + 1: a chain that does not verify.
         *
         * bc-java parks its rebuild inside the outgoing bottom key's getOtsParameters(). LmsPrivateKeyParameters is
         * sealed here (as IndexAndComponentIndexClaimedTogether also notes), and the rebuild asks the outgoing key
         * only for its LmsParameters - a field read, so there is no monitor to borrow either. The window is held
         * open by cost instead: the bottom level is a 2^10 tree, and building its replacement's public key, the
         * longest step of the rebuild, runs between the two levels. A reader checking coherence in a loop probes
         * that window hundreds of times over, so timing can only make this test miss the fault, never invent one.
         */
        [Test]
        public void MultiLevelRebuildPublishedAsOneSnapshot()
        {
            LMSigParameters topSigParams = LMSigParameters.lms_sha256_n32_h5;
            LMSigParameters bottomSigParams = LMSigParameters.lms_sha256_n32_h10;
            LMOtsParameters otsParams = LMOtsParameters.sha256_n32_w1;
            int topTwoToH = 1 << topSigParams.H, bottomTwoToH = 1 << bottomSigParams.H;
            byte[] msg = Hex.Decode("48656c6c6f");

            byte[] I = Hex.Decode("000102030405060708090a0b0c0d0e0f");
            byte[] seed = Hex.Decode("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");

            // a three-level key one signature short of exhausting both lower trees: the root has signed the middle
            // tree (q = 1), the middle tree is on its last one-time key when it signs the bottom tree, and the
            // bottom tree is on its last one-time key too
            LmsPrivateKeyParameters root = LmsKey(topSigParams, otsParams, 0, I, seed);
            var middleChild = root.DeriveChildKey();
            LmsPrivateKeyParameters middle = LmsKey(topSigParams, otsParams, topTwoToH - 1, middleChild.Item1,
                middleChild.Item2);
            var bottomChild = middle.DeriveChildKey();
            LmsPrivateKeyParameters bottom = LmsKey(bottomSigParams, otsParams, bottomTwoToH - 1, bottomChild.Item1,
                bottomChild.Item2);

            var keys = new List<LmsPrivateKeyParameters> { root, middle, bottom };
            var sig = new List<LmsSignature>
            {
                LmsTestUtilities.GenerateSign(root, middle.GetPublicKey().ToByteArray()),
                LmsTestUtilities.GenerateSign(middle, bottom.GetPublicKey().ToByteArray()),
            };

            long indexLimit = (long)topTwoToH * topTwoToH * bottomTwoToH;
            long index = (long)(topTwoToH - 1) * bottomTwoToH + (bottomTwoToH - 1);
            HssPrivateKeyParameters hss = new HssPrivateKeyParameters(3, keys, sig, index, indexLimit);

            Assert.AreSame(bottom, hss.GetKey(2), "the key was built one signature short, so the bottom key is kept");
            AssertCoherent(hss.GetKeys(), hss.GetSig());

            HssPublicKeyParameters hssPub = hss.GetPublicKey();

            // the last signature of both lower trees; the next one has to replace them both
            HssSigner signer = new HssSigner();
            signer.Init(true, hss);
            Assert.True(Verify(hssPub, signer.GenerateSignature(msg), msg));
            Assert.AreEqual(bottomTwoToH, bottom.GetIndex());
            Assert.AreEqual(topTwoToH, middle.GetIndex());

            Exception readerFailure = null;
            int checks = 0, running = 1;

            Thread reader = new Thread(() =>
            {
                try
                {
                    while (Volatile.Read(ref running) != 0)
                    {
                        // GetKeys and GetSig are two reads of the hierarchy, so a publish between them tears the
                        // pair; the read-only views are built once per snapshot, so re-reading identifies that
                        var seenKeys = hss.GetKeys();
                        var seenSig = hss.GetSig();
                        if (!ReferenceEquals(seenKeys, hss.GetKeys()))
                            continue;

                        AssertCoherent(seenKeys, seenSig);
                        Interlocked.Increment(ref checks);
                    }
                }
                catch (Exception e)
                {
                    readerFailure = e;
                }
            });
            reader.Start();

            // let the reader get going, so that a count taken across the signature is a count taken during it
            while (Volatile.Read(ref checks) == 0 && Volatile.Read(ref readerFailure) == null)
            {
                Thread.Sleep(0);
            }

            int checksBefore = Volatile.Read(ref checks);
            byte[] nextSig = signer.GenerateSignature(msg);
            int checksDuring = Volatile.Read(ref checks) - checksBefore;

            Volatile.Write(ref running, 0);
            reader.Join();

            Assert.Null(readerFailure, "a hierarchy read during the rebuild was not coherent: " + readerFailure);
            Assert.That(checksDuring, Is.GreaterThan(0), "the reader was held up by the rebuild in progress");

            // both lower levels were replaced, and the rebuilt key signs under the same public key, is coherent
            // again and round-trips
            Assert.AreNotSame(middle, hss.GetKey(1), "the middle tree was not replaced");
            Assert.AreNotSame(bottom, hss.GetKey(2), "the bottom tree was not replaced");
            Assert.True(Verify(hssPub, nextSig, msg));
            AssertCoherent(hss.GetKeys(), hss.GetSig());
            Assert.AreEqual(index + 2, hss.GetIndex());
            Assert.AreEqual(hss, HssPrivateKeyParameters.GetInstance(hss.GetEncoded()));
        }

        /*
         * Every chaining signature verifies the public key of the level below it under the public key of the level
         * that carries it.
         */
        private static void AssertCoherent(IList<LmsPrivateKeyParameters> keys, IList<LmsSignature> sig)
        {
            Assert.AreEqual(keys.Count - 1, sig.Count);

            for (int i = 0; i < sig.Count; ++i)
            {
                Assert.True(
                    LmsTestUtilities.VerifySignature(keys[i].GetPublicKey(), sig[i],
                        keys[i + 1].GetPublicKey().ToByteArray()),
                    "chaining signature at level " + i + " does not verify under the level above");
            }
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
