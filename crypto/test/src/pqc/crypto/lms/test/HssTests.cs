using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
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
                int m = LMSigParameters.GetParametersByID(ReadU32(enc, pos + 4)).M;
                int keyCoreLength = 40 + ReadU32(enc, pos + 36); // up to and including the master secret
                composer.Bytes(enc, pos, keyCoreLength);
                int cacheCount = ReadU32(enc, pos + keyCoreLength);
                pos += keyCoreLength + 4 + cacheCount * m; // skip the version 1 tree-cache field
            }
            composer.Bytes(enc, pos, enc.Length - pos); // the chaining signatures

            HssPrivateKeyParameters decoded = HssPrivateKeyParameters.GetInstance(composer.Build());

            Assert.AreEqual(generated.Level, decoded.Level);
            Assert.AreEqual(generated.GetIndex(), decoded.GetIndex());
            Assert.AreEqual(generated.IndexLimit, decoded.IndexLimit);

            HssSignature signature = Hss.GenerateSignature(decoded, Hex.Decode("ABCDEF"));
            Assert.True(Hss.VerifySignature(generated.GetPublicKey(), signature, Hex.Decode("ABCDEF")));
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

            Assert.AreEqual(1, ReadU32(enc, 0), "encoding version");

            HssPrivateKeyParameters decoded = HssPrivateKeyParameters.GetInstance(enc);

            Assert.True(decoded.Equals(generated));

            HssSignature signature = Hss.GenerateSignature(decoded, Hex.Decode("ABCDEF"));
            Assert.True(Hss.VerifySignature(generated.GetPublicKey(), signature, Hex.Decode("ABCDEF")));
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
                WriteU32(badD[i], corrupt, 4);
                var ex = Assert.Throws<IOException>(
                    () => HssPrivateKeyParameters.GetInstance(corrupt), "no exception on d = " + badD[i]);
                Assert.True(ex.Message.StartsWith("d value of HSS private key out of range"));
            }

            // index at offset 8, maxIndex at 16, both u64
            long[][] badIndex = { new long[]{ -1L, 1024L }, new long[]{ 0L, -1L }, new long[]{ 100L, 10L } };
            for (int i = 0; i != badIndex.Length; i++)
            {
                byte[] corrupt = Arrays.Clone(enc);
                WriteU64(badIndex[i][0], corrupt, 8);
                WriteU64(badIndex[i][1], corrupt, 16);
                var ex = Assert.Throws<IOException>(
                    () => HssPrivateKeyParameters.GetInstance(corrupt),
                    "no exception on index = " + badIndex[i][0] + " maxIndex = " + badIndex[i][1]);
                Assert.True(ex.Message.StartsWith("HSS private key index out of range"));
            }

            // the genuine encoding still decodes and signs verifiably
            HssPrivateKeyParameters decoded = HssPrivateKeyParameters.GetInstance(enc);
            HssSignature signature = Hss.GenerateSignature(decoded, Hex.Decode("ABCDEF"));
            Assert.True(Hss.VerifySignature(key.GetPublicKey(), signature, Hex.Decode("ABCDEF")));
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

            // another key's public key: refused
            var ex = Assert.Throws<IOException>(
                () => HssPrivateKeyParameters.GetInstance(privA, pubB));
            Assert.True(ex.Message.StartsWith("HSS private key tree cache does not match"));
        }

        private static void WriteU32(int n, byte[] buf, int off)
        {
            buf[off] = (byte)(n >> 24);
            buf[off + 1] = (byte)(n >> 16);
            buf[off + 2] = (byte)(n >> 8);
            buf[off + 3] = (byte)n;
        }

        private static void WriteU64(long n, byte[] buf, int off)
        {
            WriteU32((int)(n >> 32), buf, off);
            WriteU32((int)n, buf, off + 4);
        }

        private static HssPrivateKeyParameters GenerateKey(int d)
        {
            LmsParameters[] lmsParameters = new LmsParameters[d];
            for (int t = 0; t < d; t++)
            {
                lmsParameters[t] = new LmsParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4);
            }

            return Hss.GenerateHssKeyPair(new HssKeyGenerationParameters(lmsParameters, new SecureRandom()));
        }

        private static int ReadU32(byte[] buf, int off) =>
            (buf[off] << 24) | (buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3];

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
            // Generate, hopefully the same HSSKeyPair for the same entropy.
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
        public void Remaining()
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
        public void Sharding()
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
        public void SignUnitExhaustion()
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
                        Pack_UInt32_To_BE((uint)ctr, message, 0);
                        byte[] sig = Sign(keyPair, message);

                        Assert.AreEqual(ctr % 1024, LeafSignatureQ(keyPair, sig));

                        // Check there was a post increment in the tail end LMS key.
                        Assert.AreEqual(ctr % 1024 + 1, keyPair.GetKeys()[keyPair.Level - 1].GetIndex(), "" + ctr);

                        Assert.AreEqual(ctr + 1, keyPair.GetIndex());

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
                            Assert.AreEqual(keyPair.GetKeys()[t].GetIndex() - 1, qValues[t], "" + ctr);
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
                        Hss.IncrementIndex(keyPair);
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
            Assert.AreEqual(5UL, Pack_BE_To_UInt64(enc, 8));

            // roll the declared index back, leaving the component keys advanced
            for (int roll = 0; roll != 5; roll++)
            {
                byte[] rolled = Arrays.Clone(enc);
                Pack_UInt64_To_BE((ulong)roll, rolled, 8);
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
            int secretLen = (int)Pack_BE_To_UInt32(enc, 25 + 28 + 8);
            int cacheCount = (int)Pack_BE_To_UInt32(enc, 25 + 40 + secretLen);
            int m = LMSigParameters.lms_sha256_n32_h5.M;
            int componentSize = 4 + 4 + 4 + 16 + 4 + 4 + 4 + secretLen + 4 + cacheCount * m;
            int lastQOff = 25 + componentSize + 28;
            Assert.True(Pack_BE_To_UInt32(enc, lastQOff) > 0U, "component q should be advanced");

            byte[] qRolled = Arrays.Clone(enc);
            Pack_UInt32_To_BE(0U, qRolled, lastQOff);
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
                new LmsParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1),
                new LmsParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1) },
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
            (int)Pack_BE_To_UInt32(hssSignature, LeafSignatureOffset(key, hssSignature));

        private static int LeafSignatureType(HssPrivateKeyParameters key, byte[] hssSignature)
        {
            LmsPrivateKeyParameters leaf = key.GetKeys()[key.Level - 1];
            int h = leaf.SigParameters.H;
            int m = leaf.SigParameters.M;

            return (int)Pack_BE_To_UInt32(hssSignature, hssSignature.Length - h * m - 4);
        }

        // TODO[lms] GetSig, PeekRoot
#if false
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
                new LmsParameters[]{new LmsParameters(sigParams, otsParams), new LmsParameters(sigParams, otsParams) },
                new SecureRandom()));
            HssPrivateKeyParameters hss = (HssPrivateKeyParameters)gen.GenerateKeyPair().Private;

            HssPublicKeyParameters pubKey = hss.GetPublicKey();
            List<LmsPrivateKeyParameters> keys = new List<LmsPrivateKeyParameters>(hss.GetKeys());
            List<LmsSignature> sigs = new List<LmsSignature>(hss.GetSig());
            byte[] bottomT1 = keys[1].GetPublicKey().GetT1();

            // an index whose bottom level q moves while the root's does not: the branch where the
            // derived identifier and seed match and only the position is wrong
            HssPrivateKeyParameters moved = new HssPrivateKeyParameters(2, keys, sigs, 3, 1L << (2 * sigParams.H));

            Assert.AreSame(keys[0], moved.GetKeys()[0], "the reset replaced the root key");
            Assert.AreNotSame(keys[1], moved.GetKeys()[1], "the reset failed to reposition the bottom key");
            Assert.AreEqual(3, moved.GetKeys()[1].GetIndex());
            Assert.NotNull(moved.GetKeys()[1].PeekRootT(), "repositioning discarded the tree cache");
            Assert.True(Arrays.AreEqual(bottomT1, moved.GetKeys()[1].GetPublicKey().GetT1()),
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
#endif

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
            gen.Init(new LmsKeyGenerationParameters(new LmsParameters(sigParams, otsParams), new SecureRandom()));
            LmsPrivateKeyParameters lms = (LmsPrivateKeyParameters)gen.GenerateKeyPair().Private;

            byte[] rootT1 = lms.GetPublicKey().GetT1();
            // TODO[lms] IsTreeCachePrimed
            //Assert.True(lms.IsTreeCachePrimed(), "expected the generator to leave the cache primed");

            HssPrivateKeyParameters wrapped = new HssPrivateKeyParameters(lms, lms.GetIndex(),
                lms.GetIndex() + lms.GetUsagesRemaining());

            // TODO[lms] GetRootKey
            //Assert.AreSame(lms, wrapped.GetRootKey(), "the wrap regenerated the root key");
            Assert.AreSame(lms, wrapped.GetKeys()[0], "the wrap regenerated the root key");
            // TODO[lms] GetRootKey, IsTreeCachePrimed
            //Assert.True(wrapped.GetRootKey().IsTreeCachePrimed(), "the wrap discarded the tree cache");
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

            // TODO[lms] GetRootKey
            //Assert.AreSame(lms, advanced.GetRootKey(), "the wrap regenerated an advanced root key");
            Assert.AreSame(lms, advanced.GetKeys()[0], "the wrap regenerated an advanced root key");
            Assert.AreEqual(3, advanced.GetIndex(), "the wrap moved the index");

            // the reset itself still works: asked for a different (later - see ResetKeyToIndexRefusesToRewind)
            // position, it does reposition
            HssPrivateKeyParameters moved = new HssPrivateKeyParameters(lms, 4, 1 << sigParams.H);

            // TODO[lms] GetRootKey
            //Assert.NotSame(lms, moved.GetRootKey(), "the reset failed to reposition to a different index");
            Assert.AreNotSame(lms, moved.GetKeys()[0], "the reset failed to reposition to a different index");
            // TODO[lms] GetRootKey
            //Assert.AreEqual(4, moved.GetRootKey().GetIndex());
            Assert.AreEqual(4, moved.GetKeys()[0].GetIndex());

            // the Merkle tree is a function of I, the seed and the parameters and not of q, so the
            // repositioned key is entitled to the tree it was built from rather than a rebuild costing
            // about as much as generating the key. peekRootT is asked before getPublicKey below, which
            // would prime the cache itself and hide the difference.
            // TODO[lms] GetRootKey, PeekRootT
            //Assert.NotNull(moved.GetRootKey().PeekRootT(), "repositioning discarded the tree cache");
            // TODO[lms] GetRootKey
            //Assert.AreEqual(1 << sigParams.H, moved.GetRootKey().IndexLimit,
            //    "repositioning narrowed the range of the key");
            Assert.AreEqual(1 << sigParams.H, moved.GetKeys()[0].IndexLimit,
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
            gen.Init(new LmsKeyGenerationParameters(new LmsParameters(sigParams, otsParams), new SecureRandom()));
            LmsPrivateKeyParameters lms = (LmsPrivateKeyParameters)gen.GenerateKeyPair().Private;
            for (int i = 0; i < 3; ++i)
            {
                Lms.GenerateSign(lms, msg);
            }
            Assert.AreEqual(3, lms.GetIndex());

            Assert.Throws<InvalidOperationException>(() => new HssPrivateKeyParameters(lms, 2, twoToH));
            Assert.AreEqual(3, new HssPrivateKeyParameters(lms, 3, twoToH).GetIndex());
            Assert.AreEqual(4, new HssPrivateKeyParameters(lms, 4, twoToH).GetKeys()[0].GetIndex());

            // two levels: the root is post-incremented past the child it signed, the bottom reads its q directly
            HssPrivateKeyParameters hss = Hss.GenerateHssKeyPair(new HssKeyGenerationParameters(
                new LmsParameters[]
                {
                    new LmsParameters(sigParams, otsParams),
                    new LmsParameters(sigParams, otsParams),
                }, new SecureRandom()));
            for (int i = 0; i < twoToH + 1; ++i)
            {
                Hss.GenerateSignature(hss, msg);
            }
            var keys = hss.GetKeys();
            var sig = hss.GetSig();
            long limit = (long)twoToH * twoToH;
            Assert.AreEqual(2, keys[0].GetIndex());
            Assert.AreEqual(1, keys[1].GetIndex());

            // back one leaf within the current bottom tree
            Assert.Throws<InvalidOperationException>(() => new HssPrivateKeyParameters(2, keys, sig, twoToH, limit));
            // back into the previous bottom tree, which the root has already signed and moved past
            Assert.Throws<InvalidOperationException>(() => new HssPrivateKeyParameters(2, keys, sig, 5, limit));
            // the position the keys are at, and one further on, are both fine
            Assert.AreEqual(twoToH + 1, new HssPrivateKeyParameters(2, keys, sig, twoToH + 1, limit).GetIndex());
            HssPrivateKeyParameters forward = new HssPrivateKeyParameters(2, keys, sig, twoToH + 8, limit);
            Assert.AreEqual(8, forward.GetKeys()[1].GetIndex());
            Assert.True(Hss.VerifySignature(hss.GetPublicKey(), Hss.GenerateSignature(forward, msg), msg));
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

            HssPrivateKeyParameters hss = Hss.GenerateHssKeyPair(new HssKeyGenerationParameters(
                new LmsParameters[] { new LmsParameters(sigParams, otsParams) }, new SecureRandom()));
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
            Assert.AreEqual(0U, Pack_BE_To_UInt32(hssSig, 0));
            byte[] lmsPart = Arrays.CopyOfRange(hssSig, 4, hssSig.Length);
            Assert.AreEqual(5, LmsSignature.GetInstance(lmsPart).Q);
            Assert.True(VerifyLms(hssPub.LmsPublicKey, lmsPart, msg));

            // a shard taken now continues from the position the signatures reached
            HssPrivateKeyParameters shard = hss.ExtractKeyShard(3);
            Assert.AreEqual(6, shard.GetIndex());
            Assert.AreEqual(9, hss.GetIndex());
            Assert.AreEqual(6, Hss.GenerateSignature(shard, msg).Signature.Q);
            Assert.AreEqual(9, Hss.GenerateSignature(hss, msg).Signature.Q);
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
            LmsSignature chain = Lms.GenerateSign(root, bottom.GetPublicKey().ToByteArray());

            HssPrivateKeyParameters hss = new HssPrivateKeyParameters(2,
                new List<LmsPrivateKeyParameters> { root, bottom }, new List<LmsSignature> { chain }, 0,
                (long)twoToH * twoToH);

            Assert.AreSame(bottom, hss.GetKeys()[1], "the bottom key was regenerated, so its usage limit is gone");

            // the one signature the bottom key can give
            HssSignature first = Hss.GenerateSignature(hss, msg);
            Assert.True(Hss.VerifySignature(hss.GetPublicKey(), first, msg));
            Assert.AreEqual(1, hss.GetIndex());

            // the next passes the range test but is refused by the bottom key's own claim
            Assert.Throws<ExhaustedPrivateKeyException>(() => Hss.GenerateSignature(hss, msg));
            Assert.AreEqual(1, hss.GetIndex(), "a refused claim moved the HSS index");
            Assert.AreEqual(1, hss.GetKeys()[1].GetIndex());

            // and the key still encodes to something its own decoder accepts
            HssPrivateKeyParameters decoded = HssPrivateKeyParameters.GetInstance(hss.GetEncoded());
            Assert.AreEqual(1, decoded.GetIndex());

            // contention sweep: signatures in flight, encodings taken and decoded throughout
            HssPrivateKeyParameters sweep = Hss.GenerateHssKeyPair(new HssKeyGenerationParameters(
                new LmsParameters[]
                {
                    new LmsParameters(sigParams, otsParams),
                    new LmsParameters(sigParams, otsParams),
                }, new SecureRandom()));
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
                Assert.True(Hss.VerifySignature(sweepPub, signature, msg));

                LmsPublicKeyParameters bottomPub = signature.GetSignedPubKeys()[0].PublicKey;
                Assert.True(leavesUsed.Add(Hex.ToHexString(bottomPub.GetI()) + ":" + signature.Signature.Q),
                    "a one-time key was used twice");
            }
        }

        private static uint Pack_BE_To_UInt32(byte[] bs, int off)
        {
            return (uint)bs[off] << 24
                | (uint)bs[off + 1] << 16
                | (uint)bs[off + 2] << 8
                | bs[off + 3];
        }

        private static ulong Pack_BE_To_UInt64(byte[] bs, int off)
        {
            uint hi = Pack_BE_To_UInt32(bs, off);
            uint lo = Pack_BE_To_UInt32(bs, off + 4);
            return ((ulong)hi << 32) | (ulong)lo;
        }

        private static void Pack_UInt32_To_BE(uint n, byte[] bs, int off)
        {
            bs[off] = (byte)(n >> 24);
            bs[off + 1] = (byte)(n >> 16);
            bs[off + 2] = (byte)(n >> 8);
            bs[off + 3] = (byte)n;
        }

        private static void Pack_UInt64_To_BE(ulong n, byte[] bs, int off)
        {
            Pack_UInt32_To_BE((uint)(n >> 32), bs, off);
            Pack_UInt32_To_BE((uint)n, bs, off + 4);
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
