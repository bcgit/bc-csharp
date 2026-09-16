using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Pqc.Crypto.Lms.Tests
{
    [TestFixture]
    public class LmsTests
    {
        [Test]
        public void TestCoefFunc()
        {
            byte[] S = Hex.Decode("1234");
            Assert.AreEqual(0, LMOts.Coef(S, 7, 1));
            Assert.AreEqual(1, LMOts.Coef(S, 0, 4));
        }

        [Test]
        public void TestPrivateKeyRound()
        {
            LMOtsParameters parameter = LMOtsParameters.sha256_n32_w4;

            byte[] seed = Hex.Decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
            byte[] I = Hex.Decode("d08fabd4a2091ff0a8cb4ed834e74534");

            LMOtsPrivateKey privateKey = new LMOtsPrivateKey(parameter, I, 0, seed);
            LMOtsPublicKey publicKey = LMOts.LmsOtsGeneratePublicKey(privateKey);

            byte[] ms = new byte[32];
            for (int t = 0; t < ms.Length; t++)
            {
                ms[t] = (byte)t;
            }

            LmsContext ctx = privateKey.GetSignatureContext(null, null);

            ctx.BlockUpdate(ms, 0, ms.Length);

            byte[] Q = new byte[parameter.N + 2];
            ctx.OutputQ(Q, 0);

            LMOtsSignature sig = LMOts.LMOtsGenerateSignature(privateKey, Q, ctx.C);
            Assert.True(LMOts.LMOtsValidateSignature(publicKey, sig, ms, false));

            // Recreate signature
            {
                byte[] recreatedSignature = sig.GetEncoded();
                Assert.True(LMOts.LMOtsValidateSignature(publicKey, LMOtsSignature.GetInstance(recreatedSignature), ms, false));
            }

            // Recreate public key.
            {
                byte[] recreatedPubKey = Arrays.Clone(publicKey.GetEncoded());
                Assert.True(LMOts.LMOtsValidateSignature(LMOtsPublicKey.GetInstance(recreatedPubKey), sig, ms, false));
            }

            // Vandalise signature
            {

                byte[] vandalisedSignature = sig.GetEncoded();
                vandalisedSignature[256] ^= 1; // Single bit error
                Assert.False(LMOts.LMOtsValidateSignature(publicKey, LMOtsSignature.GetInstance(vandalisedSignature), ms, false));
            }

            // Vandalise public key.
            {
                byte[] vandalisedPubKey = Arrays.Clone(publicKey.GetEncoded());
                vandalisedPubKey[50] ^= 1;
                Assert.False(LMOts.LMOtsValidateSignature(LMOtsPublicKey.GetInstance(vandalisedPubKey), sig, ms, false));
            }

            //
            // check incorrect alg type is detected.
            //
            try
            {
                byte[] vandalisedPubKey = Arrays.Clone(publicKey.GetEncoded());
                vandalisedPubKey[3] += 1;
                LMOts.LMOtsValidateSignature(LMOtsPublicKey.GetInstance(vandalisedPubKey), sig, ms, false);
                Assert.True(false, "Must fail as public key type not match signature type.");
            }
            catch (LmsException ex)
            {
                Assert.True(ex.Message.Contains("public key and signature ots types do not match"));
            }
        }

        [Test]
        public void TestLMS()
        {
            byte[] msg = Hex.Decode("54686520656e756d65726174696f6e20\n" +
                                    "696e2074686520436f6e737469747574\n" +
                                    "696f6e2c206f66206365727461696e20\n" +
                                    "7269676874732c207368616c6c206e6f\n" +
                                    "7420626520636f6e7374727565642074\n" +
                                    "6f2064656e79206f7220646973706172\n" +
                                    "616765206f7468657273207265746169\n" +
                                    "6e6564206279207468652070656f706c\n" +
                                    "652e0a");

            byte[] seed = Hex.Decode("a1c4696e2608035a886100d05cd99945eb3370731884a8235e2fb3d4d71f2547");
            int level = 1;
            LmsPrivateKeyParameters lmsPrivateKey = LmsTestUtilities.GenerateKey(
                LMSigParameters.GetParametersByID(5),
                LMOtsParameters.GetParametersByID(4),
                level, Hex.Decode("215f83b7ccb9acbcd08db97b0d04dc2b"), seed);

            LmsPublicKeyParameters publicKey = lmsPrivateKey.GetPublicKey();

            lmsPrivateKey.ExtractKeyShard(3);

            LmsSignature signature = LmsTestUtilities.GenerateSign(lmsPrivateKey, msg);
            Assert.True(LmsTestUtilities.VerifySignature(publicKey, signature, msg));

            // Serialize / Deserialize
            Assert.True(LmsTestUtilities.VerifySignature(
                LmsPublicKeyParameters.GetInstance(publicKey.GetEncoded()),
                LmsSignature.GetInstance(signature.GetEncoded()), msg));

            //
            // Vandalise signature.
            //
            {
                byte[] bustedSig = Arrays.Clone(signature.GetEncoded());
                bustedSig[100] ^= 1;
                Assert.False(LmsTestUtilities.VerifySignature(publicKey, LmsSignature.GetInstance(bustedSig), msg));
            }

            //
            // Vandalise message
            //
            {
                byte[] msg2 = Arrays.Clone(msg);
                msg2[10] ^= 1;
                Assert.False(LmsTestUtilities.VerifySignature(publicKey, signature, msg2));
            }
        }

        [Test]
        public void TestContextSingleUse()
        {
            LMOtsParameters parameter = LMOtsParameters.sha256_n32_w4;

            byte[] seed = Hex.Decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
            byte[] I = Hex.Decode("d08fabd4a2091ff0a8cb4ed834e74534");

            LMOtsPrivateKey privateKey = new LMOtsPrivateKey(parameter, I, 0, seed);
            LMOtsPublicKey publicKey = LMOts.LmsOtsGeneratePublicKey(privateKey);

            byte[] ms = new byte[32];
            for (int t = 0; t < ms.Length; t++)
            {
                ms[t] = (byte)t;
            }

            LmsContext ctx = privateKey.GetSignatureContext(null, null);

            ctx.BlockUpdate(ms, 0, ms.Length);

            byte[] Q = new byte[parameter.N + 2];
            ctx.OutputQ(Q, 0);

            LMOtsSignature sig = LMOts.LMOtsGenerateSignature(privateKey, Q, ctx.C);
            Assert.True(LMOts.LMOtsValidateSignature(publicKey, sig, ms, false));

            Assert.Throws<InvalidOperationException>(() => ctx.Update(1), "Digest reuse after signature taken.");
            Assert.Throws<InvalidOperationException>(() => ctx.OutputQ(Q, 0), "Q taken twice from one context.");
        }

        /**
         * GetQ is superseded by OutputQ but must keep working: it returns a buffer sized for the largest N over
         * the parameter sets, plus the two bytes a caller needs for the checksum.
         */
        [Test]
        public void TestObsoleteGetQMatchesOutputQ()
        {
            LMOtsParameters parameter = LMOtsParameters.sha256_n24_w4;

            byte[] seed = Hex.Decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
            byte[] I = Hex.Decode("d08fabd4a2091ff0a8cb4ed834e74534");

            LMOtsPrivateKey privateKey = new LMOtsPrivateKey(parameter, I, 0, seed);

            byte[] ms = new byte[32];

            LmsContext ctx = privateKey.GetSignatureContext(null, null);
            ctx.BlockUpdate(ms, 0, ms.Length);

            byte[] Q = new byte[parameter.N + 2];
            Assert.AreEqual(parameter.N, ctx.OutputQ(Q, 0));

            LmsContext ctx2 = privateKey.GetSignatureContext(null, null);
            ctx2.BlockUpdate(ms, 0, ms.Length);

            byte[] legacyQ = ctx2.GetQ();

            Assert.AreEqual(34, legacyQ.Length);
            Assert.True(Arrays.AreEqual(Q, 0, parameter.N, legacyQ, 0, parameter.N));

            // The bytes past N are the caller's to fill in, and GetQ leaves them zeroed.
            Assert.True(Arrays.AreEqual(new byte[legacyQ.Length - parameter.N], Arrays.CopyOfRange(legacyQ,
                parameter.N, legacyQ.Length)));
        }

        /**
         * The context absorbs I || u32str(q) || u16str(D_MESG) || C at construction and must be finalized exactly
         * once, by OutputQ. IDigest.DoFinal would hand back something that looks like Q while resetting the
         * digest, leaving OutputQ to hash nothing at all; Reset would discard the prefix irrecoverably. Both
         * must refuse.
         */
        [Test]
        public void TestContextRejectsDigestFinalization()
        {
            LMOtsParameters parameter = LMOtsParameters.sha256_n32_w4;

            byte[] seed = Hex.Decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
            byte[] I = Hex.Decode("d08fabd4a2091ff0a8cb4ed834e74534");

            LMOtsPrivateKey privateKey = new LMOtsPrivateKey(parameter, I, 0, seed);

            LmsContext ctx = privateKey.GetSignatureContext(null, null);

            Assert.Throws<NotSupportedException>(() => ctx.DoFinal(new byte[parameter.N], 0));
            Assert.Throws<NotSupportedException>(() => ctx.Reset());
// NOTE: .NET Core 3.1 has Span<T>, but is tested against our .NET Standard 2.0 assembly.
//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Assert.Throws<NotSupportedException>(() => ctx.DoFinal(new byte[parameter.N].AsSpan()));
#endif

            // The refusals left the context usable.
            byte[] ms = new byte[32];
            ctx.BlockUpdate(ms, 0, ms.Length);

            LMOtsPublicKey publicKey = LMOts.LmsOtsGeneratePublicKey(privateKey);
            byte[] Q = new byte[parameter.N + 2];
            ctx.OutputQ(Q, 0);

            LMOtsSignature sig = LMOts.LMOtsGenerateSignature(privateKey, Q, ctx.C);
            Assert.True(LMOts.LMOtsValidateSignature(publicKey, sig, ms, false));
        }

        /**
         * The legacy LM_OTS entry points carry a pre-hashed flag they cannot honour: signing has no parameter for
         * the randomizer C that the caller hashed into Q, and verification ignores the flag entirely.
         */
        [Test]
        public void TestPreHashedFlagRefused()
        {
            LMOtsParameters parameter = LMOtsParameters.sha256_n32_w4;

            byte[] seed = Hex.Decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
            byte[] I = Hex.Decode("d08fabd4a2091ff0a8cb4ed834e74534");

            LMOtsPrivateKey privateKey = new LMOtsPrivateKey(parameter, I, 0, seed);
            LMOtsPublicKey publicKey = LMOts.LmsOtsGeneratePublicKey(privateKey);

            byte[] ms = new byte[32];

            LmsContext ctx = privateKey.GetSignatureContext(null, null);
            ctx.BlockUpdate(ms, 0, ms.Length);
            byte[] Q = new byte[parameter.N + 2];
            ctx.OutputQ(Q, 0);

            LMOtsSignature sig = LMOts.LMOtsGenerateSignature(privateKey, Q, ctx.C);

            Assert.Throws<ArgumentException>(
                () => LMOts.lm_ots_generate_signature(null, privateKey, null, ms, preHashed: true));
            Assert.Throws<ArgumentException>(
                () => LMOts.LMOtsValidateSignature(publicKey, sig, ms, prehashed: true));
        }

        /**
         * Regression test for https://github.com/bcgit/bc-java/issues/2365 - GetEncoded() must carry the top of
         * the Merkle tree so that the first signature made after a key is decoded does not have to rebuild the
         * whole tree (which costs about as much as key generation). Also checks that the legacy encoding, which
         * carries no cache, is still accepted.
         */
        [Test]
        public void TestTreeCachePersistence()
        {
            byte[] seed = Hex.Decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
            byte[] I = Hex.Decode("d08fabd4a2091ff0a8cb4ed834e74534");
            byte[] msg = Hex.Decode("54686520656e756d65726174696f6e20696e2074686520436f6e737469747574");

            LMSigParameters sigParams = LMSigParameters.lms_sha256_n32_h5;
            LMOtsParameters otsParams = LMOtsParameters.sha256_n32_w4;

            LmsPrivateKeyParameters privateKey = LmsTestUtilities.GenerateKey(sigParams, otsParams, 0, I, seed);
            LmsPublicKeyParameters publicKey = privateKey.GetPublicKey();

            int h = sigParams.H;
            int m = sigParams.M;
            int cacheTop = System.Math.Min(64, 1 << (h + 1));

            byte[] enc = privateKey.GetEncoded();

            // 72 byte body + u32 node count + (cacheTop - 1) nodes of m bytes each. The version stays 0 and the
            // cache is appended as trailing data, matching the bc-java interchange format.
            Assert.AreEqual(0, ReadU32(enc, 0));
            Assert.AreEqual(cacheTop - 1, ReadU32(enc, 72));
            Assert.AreEqual(72 + 4 + (cacheTop - 1) * m, enc.Length);

            // The first cached node is the root of the Merkle tree - it must match the public key's T[1].
            byte[] t1 = publicKey.GetT1();
            Assert.True(Arrays.AreEqual(t1, 0, t1.Length, enc, 76, 76 + m));

            // The decoded key signs correctly and byte-identically to a fresh key at the same index.
            LmsPrivateKeyParameters decoded = LmsPrivateKeyParameters.GetInstance(enc);
            LmsSignature sigFromDecoded = LmsTestUtilities.GenerateSign(decoded, msg);
            Assert.True(LmsTestUtilities.VerifySignature(publicKey, sigFromDecoded, msg));

            LmsPrivateKeyParameters fresh = LmsTestUtilities.GenerateKey(sigParams, otsParams, 0, I, seed);
            Assert.True(Arrays.AreEqual(sigFromDecoded.GetEncoded(), LmsTestUtilities.GenerateSign(fresh, msg).GetEncoded()));

            // A corrupted cache node is caught at decode: each cached interior node is recomputed from its
            // cached children and compared before the cache is primed into the tree (bc-java github #2414).
            byte[] corruptedEnc = Arrays.Clone(enc);
            corruptedEnc[76 + 2 * m] ^= 1;
            var ex = Assert.Throws<IOException>(
                () => LmsPrivateKeyParameters.GetInstance(corruptedEnc));
            Assert.True(ex.Message.StartsWith("LMS private key tree cache inconsistent at node"));

            // An encoding with no trailing cache - what an older release writes - must still decode and sign
            // correctly.
            byte[] legacyEnc = Composer.Compose()
                .U32Str(0)
                .U32Str(sigParams.ID)
                .U32Str(otsParams.ID)
                .Bytes(I)
                .U32Str(0)
                .U32Str(1 << h)
                .U32Str(seed.Length)
                .Bytes(seed)
                .Build();
            Assert.AreEqual(72, legacyEnc.Length);

            LmsPrivateKeyParameters legacy = LmsPrivateKeyParameters.GetInstance(legacyEnc);
            Assert.True(LmsTestUtilities.VerifySignature(publicKey, LmsTestUtilities.GenerateSign(legacy, msg), msg));
        }

        [Test]
        public void TestMalformedPrivateKeyTreeCache()
        {
            byte[] seed = Hex.Decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
            byte[] I = Hex.Decode("d08fabd4a2091ff0a8cb4ed834e74534");

            LMSigParameters sigParams = LMSigParameters.lms_sha256_n32_h5;
            LMOtsParameters otsParams = LMOtsParameters.sha256_n32_w4;
            int m = sigParams.M;

            //
            // The number of nodes cached is capped (matching the interned-key table in the bc-java
            // implementation), so read the limit off a freshly generated key of the same parameters rather than
            // hard-coding it - the limit moves if that cap is resized.
            //
            byte[] sampleEnc = LmsTestUtilities.GenerateKey(sigParams, otsParams, 0, I, seed).GetEncoded();
            int cacheCountLimit = ReadU32(sampleEnc, 40 + m);

            // A cache at the limit is accepted. The node values have to be the real ones: they are a
            // deterministic function of I, the master secret and the parameters, and are checked against each
            // other at decode (bc-java github #2414), so the sample key's own encoding is used rather than a
            // run of dummy bytes. The cache survives the round trip byte for byte.
            Assert.True(Arrays.AreEqual(sampleEnc, LmsPrivateKeyParameters.GetInstance(sampleEnc).GetEncoded()));

            // A cache whose count and length are in range but whose node values are not the ones the key
            // derives is refused rather than primed into the tree (bc-java github #2414).
            byte[] zeroed = Composer.Compose()
                .U32Str(0)
                .U32Str(sigParams.ID)
                .U32Str(otsParams.ID)
                .Bytes(I)
                .U32Str(0)
                .U32Str(1 << sigParams.H)
                .U32Str(seed.Length)
                .Bytes(seed)
                .U32Str(cacheCountLimit)
                .Bytes(new byte[cacheCountLimit * m])
                .Build();
            var ex0 = Assert.Throws<IOException>(
                () => LmsPrivateKeyParameters.GetInstance(zeroed));
            Assert.True(ex0.Message.StartsWith("LMS private key tree cache inconsistent at node"));

            byte[] beyondLimit = Composer.Compose()
                .U32Str(0)
                .U32Str(sigParams.ID)
                .U32Str(otsParams.ID)
                .Bytes(I)
                .U32Str(0)
                .U32Str(1 << sigParams.H)
                .U32Str(seed.Length)
                .Bytes(seed)
                .U32Str(cacheCountLimit + 1)
                .Build();
            var ex1 = Assert.Throws<IOException>(
                () => LmsPrivateKeyParameters.GetInstance(beyondLimit));
            Assert.True(ex1.Message.StartsWith("tree cache node count out of range"));

            byte[] truncated = Composer.Compose()
                .U32Str(0)
                .U32Str(sigParams.ID)
                .U32Str(otsParams.ID)
                .Bytes(I)
                .U32Str(0)
                .U32Str(1 << sigParams.H)
                .U32Str(seed.Length)
                .Bytes(seed)
                .U32Str(cacheCountLimit)
                .Bytes(new byte[cacheCountLimit * m - 1])
                .Build();
            // Either the up-front length check or the bounded read may detect the truncation
            Assert.Catch<IOException>(() => LmsPrivateKeyParameters.GetInstance(truncated));
        }

        /// <summary>
        /// Every single-byte corruption of the tree cache is rejected at decode. Before github bc-java #2414 the cached
        /// node values were read but never checked, so a corrupt cache was primed into the tree: altering the root
        /// changed the public key the key reported (and survived a re-encode), and altering other nodes produced
        /// signatures that did not verify - both silently.
        /// </summary>
        [Test]
        public void TreeCacheCorruptionRejected()
        {
            LMSigParameters sigParams = LMSigParameters.lms_sha256_n32_h5;
            LMOtsParameters otsParams = LMOtsParameters.sha256_n32_w1;
            int m = sigParams.M;

            LmsKeyPairGenerator gen = new LmsKeyPairGenerator();
            gen.Init(new LmsKeyGenerationParameters(new LmsParameters(sigParams, otsParams), new SecureRandom()));
            LmsPrivateKeyParameters priv = (LmsPrivateKeyParameters)gen.GenerateKeyPair().Private;
            byte[] enc = priv.GetEncoded();

            int countOff = 40 + ReadU32(enc, 36);
            int cacheCount = ReadU32(enc, countOff);
            int cacheOff = countOff + 4;
            Assert.Greater(cacheCount, 0, "expected a primed cache to corrupt");

            for (int r = 1; r <= cacheCount; r++)
            {
                for (int b = 0; b < m; b++)
                {
                    byte[] corrupt = Arrays.Clone(enc);
                    corrupt[cacheOff + (r - 1) * m + b] ^= 0x01;
                    try
                    {
                        LmsPrivateKeyParameters.GetInstance(corrupt);
                        Assert.Fail("no exception on corrupt cache node " + r + " byte " + b);
                    }
                    catch (IOException e)
                    {
                        Assert.That(e.Message.StartsWith("LMS private key tree cache inconsistent at node"));
                    }
                }
            }

            // the untouched encoding still decodes, primes and signs verifiably
            LmsPrivateKeyParameters decoded = LmsPrivateKeyParameters.GetInstance(enc);
            // TODO[lms] IsTreeCachePrimed
            //Assert.True(decoded.IsTreeCachePrimed());
            byte[] msg = Hex.Decode("48656c6c6f");
            Assert.True(Verify(priv.GetPublicKey(), Sign(decoded, msg), msg));
        }

        /// <summary>
        /// The key parameter constructors apply the checks the decoder applies, so a key built directly cannot be one
        /// the decoder would refuse. <see cref="LmsPrivateKeyParameters"/> accepted an identifier of any length
        /// although the decoder reads exactly 16 bytes - such a key encoded but could not be read back - and left q,
        /// maxQ and the seed length unchecked although all three are checked at decode;
        /// <see cref="HssPrivateKeyParameters"/> checked neither its level count nor that it had been given a component
        /// key and a chaining signature per level, and then indexed both lists.
        /// </summary>
        [Test]
        public void KeyParameterConstructorsValidate()
        {
            LMSigParameters sigParams = LMSigParameters.lms_sha256_n32_h5;
            LMOtsParameters otsParams = LMOtsParameters.sha256_n32_w1;
            int twoToH = 1 << sigParams.H;
            byte[] I = new byte[16];
            byte[] seed = new byte[sigParams.M];

            // the well-formed case is unaffected
            Assert.NotNull(new LmsPrivateKeyParameters(sigParams, otsParams, 0, I, twoToH, seed));

            ExpectBadArgument("LMS key identifier I must be 16 bytes", sigParams, otsParams, 0, new byte[15], twoToH,
                seed);
            ExpectBadArgument("LMS key identifier I must be 16 bytes", sigParams, otsParams, 0, new byte[17], twoToH,
                seed);
            ExpectBadArgument("LMS key identifier I must be 16 bytes", sigParams, otsParams, 0, null, twoToH, seed);
            ExpectBadArgument("LMS private key needs both parameter sets", sigParams, null, 0, I, twoToH, seed);
            ExpectBadArgument("master secret length is less than " + sigParams.M, sigParams, otsParams, 0, I, twoToH,
                new byte[1]);
            ExpectBadArgument("LMS private key q/maxQ out of range: q=-1 maxQ=" + twoToH + " 2^h=" + twoToH, sigParams,
                otsParams, -1, I, twoToH, seed);
            ExpectBadArgument("LMS private key q/maxQ out of range: q=0 maxQ=" + (twoToH + 1) + " 2^h=" + twoToH,
                sigParams, otsParams, 0, I, twoToH + 1, seed);
            ExpectBadArgument("LMS private key q/maxQ out of range: q=5 maxQ=4 2^h=" + twoToH, sigParams, otsParams, 5,
                I, 4, seed);

            // and a key that survives the constructor round-trips through the decoder
            LmsPrivateKeyParameters key = new LmsPrivateKeyParameters(sigParams, otsParams, 0, I, twoToH, seed);
            Assert.NotNull(LmsPrivateKeyParameters.GetInstance(key.GetEncoded()));

            // HSS: level count, list sizes and the index pair
            List<LmsPrivateKeyParameters> one = new List<LmsPrivateKeyParameters>(){ key };
            List<LmsSignature> none = new List<LmsSignature>();

            ExpectBadHss("L value of HSS private key out of range: 0", 0, one, none, 0, twoToH);
            ExpectBadHss("L value of HSS private key out of range: 9", 9, one, none, 0, twoToH);
            ExpectBadHss("HSS private key needs one component key per level", 2, one, none, 0, twoToH);
            ExpectBadHss("HSS private key index out of range: index=5 indexLimit=4", 1, one, none, 5, 4);
            ExpectBadHss("HSS private key index out of range: index=-1 indexLimit=4", 1, one, none, -1, 4);

            // the well-formed single-level case still builds
            Assert.NotNull(new HssPrivateKeyParameters(1, one, none, 0, twoToH));
        }

        private static void ExpectBadArgument(String message, LMSigParameters sigParams, LMOtsParameters otsParams,
            int q, byte[] I, int maxQ, byte[] seed)
        {
            try
            {
                new LmsPrivateKeyParameters(sigParams, otsParams, q, I, maxQ, seed);
                Assert.Fail("no exception for: " + message);
            }
            catch (ArgumentException e)
            {
                Assert.That(e.Message.StartsWith(message));
            }
        }

        private static void ExpectBadHss(String message, int l, List<LmsPrivateKeyParameters> keys,
            List<LmsSignature> sig, long index, long indexLimit)
        {
            try
            {
                new HssPrivateKeyParameters(l, keys, sig, index, indexLimit);
                Assert.Fail("no exception for: " + message);
            }
            catch (ArgumentException e)
            {
                Assert.That(e.Message.StartsWith(message));
            }
        }

        /// <summary>
        /// A tree cache node count that is not a complete top of tree - 2^k - 1 nodes - is refused at decode. The
        /// consistency check recomputes a cached node from its two cached children, so a node with no cached sibling
        /// pair above it would be read but never checked: at a count of 1 or 2 that is the root itself, so a corrupted
        /// root was primed and the key reported the wrong public key, and at any even count it is the last node, so a
        /// corrupted one survived and was carried forward by the next getEncoded().This writer only ever emits 63, or
        /// 31 for a height-5 shard.
        /// </summary>
        [Test]
        public void TreeCacheIncompleteTopOfTreeRejected()
        {
            LMSigParameters sigParams = LMSigParameters.lms_sha256_n32_h5;
            LMOtsParameters otsParams = LMOtsParameters.sha256_n32_w1;
            int m = sigParams.M;

            LmsKeyPairGenerator gen = new LmsKeyPairGenerator();
            gen.Init(new LmsKeyGenerationParameters(new LmsParameters(sigParams, otsParams), new SecureRandom()));
            LmsPrivateKeyParameters priv = (LmsPrivateKeyParameters)gen.GenerateKeyPair().Private;
            byte[] enc = priv.GetEncoded();

            int countOff = 40 + ReadU32(enc, 36);
            int cacheCount = ReadU32(enc, countOff);
            Assert.AreEqual(63, cacheCount, "this writer should emit a full top of tree");

            int[] incomplete = new int[]{ 1, 2, 4, 5, 6, 8, 30, 62 };
            for (int i = 0; i != incomplete.Length; i++)
            {
                int count = incomplete[i];
                try
                {
                    LmsPrivateKeyParameters.GetInstance(WithNodeCount(enc, countOff, m, count));
                    Assert.Fail("no exception on an incomplete tree cache of " + count + " nodes");
                }
                catch (IOException e)
                {
                    Assert.AreEqual("tree cache node count is not a complete top of tree: " + count, e.Message);
                }
            }

            // the shapes this writer produces, and an absent cache, are still accepted
            int[] complete = new int[]{ 0, 3, 7, 15, 31, 63 };
            for (int i = 0; i != complete.Length; i++)
            {
                LmsPrivateKeyParameters decoded = LmsPrivateKeyParameters.GetInstance(
                    WithNodeCount(enc, countOff, m, complete[i]));
                Assert.True(Arrays.AreEqual(priv.GetPublicKey().GetEncoded(), decoded.GetPublicKey().GetEncoded()),
                    "complete top of tree of " + complete[i] + " nodes was refused");
            }

            // a corrupted node in each refused shape is what the restriction is there to stop reaching
            // the tree: at count 1 and 2 the root, at count 62 the last node
            int[][] corruptCases = new int[][]{ new int[]{ 1, 1 }, new int[] { 2, 1 }, new int[] { 62, 62 } };
            for (int i = 0; i != corruptCases.Length; i++)
            {
                byte[] truncated = WithNodeCount(enc, countOff, m, corruptCases[i][0]);
                truncated[countOff + 4 + (corruptCases[i][1] - 1) * m] ^= 0x01;
                try
                {
                    LmsPrivateKeyParameters.GetInstance(truncated);
                    Assert.Fail("corrupt node " + corruptCases[i][1] + " accepted at count " + corruptCases[i][0]);
                }
                catch (IOException e)
                {
                    Assert.AreEqual("tree cache node count is not a complete top of tree: " + corruptCases[i][0],
                        e.Message);
                }
            }
        }

        /// <summary>
        /// The passed in encoding with its tree cache cut down to the first nodeCount nodes.
        /// </summary>
        private static byte[] WithNodeCount(byte[] enc, int countOff, int m, int nodeCount)
        {
            byte[] rebuilt = new byte[countOff + 4 + nodeCount * m];

            Array.Copy(enc, 0, rebuilt, 0, countOff);
            WriteU32(nodeCount, rebuilt, countOff);
            Array.Copy(enc, countOff + 4, rebuilt, countOff + 4, nodeCount * m);

            return rebuilt;
        }

        /// <summary>
        /// Every single-byte corruption of the tree cache is rejected at decode, and the one-time index q and its limit
        /// maxQ are range checked. Both were unchecked before github bc-java #2414: a corrupt cache primed into the
        /// tree yields signatures that do not verify, and a q outside the tree signs with a one-time key the public key
        /// does not commit to.
        /// </summary>
        [Test]
        public void TestPrivateKeyDecodeValidation()
        {
            byte[] seed = Hex.Decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
            byte[] I = Hex.Decode("d08fabd4a2091ff0a8cb4ed834e74534");

            LMSigParameters sigParams = LMSigParameters.lms_sha256_n32_h5;
            LMOtsParameters otsParams = LMOtsParameters.sha256_n32_w4;
            int m = sigParams.M;

            LmsPrivateKeyParameters priv = LmsTestUtilities.GenerateKey(sigParams, otsParams, 0, I, seed);
            byte[] enc = priv.GetEncoded();

            int countOff = 40 + ReadU32(enc, 36);
            int cacheCount = ReadU32(enc, countOff);
            int cacheOff = countOff + 4;
            Assert.True(cacheCount > 0, "expected a primed cache to corrupt");

            for (int r = 1; r <= cacheCount; r++)
            {
                byte[] corrupt = Arrays.Clone(enc);
                corrupt[cacheOff + (r - 1) * m] ^= 0x01;
                var ex = Assert.Throws<IOException>(
                    () => LmsPrivateKeyParameters.GetInstance(corrupt), "no exception on corrupt cache node " + r);
                Assert.True(ex.Message.StartsWith("LMS private key tree cache inconsistent at node"));
            }

            int twoToH = 1 << sigParams.H;
            int[][] bad = { new int[]{ twoToH + 1, 1000 }, new int[]{ -1, twoToH },
                new int[]{ int.MinValue, twoToH }, new int[]{ 0, twoToH + 1 }, new int[]{ 0, -1 },
                new int[]{ 4, 3 } };
            for (int i = 0; i != bad.Length; i++)
            {
                byte[] bogus = Composer.Compose()
                    .U32Str(0)
                    .U32Str(sigParams.ID)
                    .U32Str(otsParams.ID)
                    .Bytes(I)
                    .U32Str(bad[i][0])
                    .U32Str(bad[i][1])
                    .U32Str(seed.Length)
                    .Bytes(seed)
                    .Build();
                var ex = Assert.Throws<IOException>(
                    () => LmsPrivateKeyParameters.GetInstance(bogus),
                    "no exception on q=" + bad[i][0] + " maxQ=" + bad[i][1]);
                Assert.True(ex.Message.StartsWith("LMS private key q/maxQ out of range"));
            }

            // the untouched encoding still decodes, and the cache survives the round trip
            Assert.True(Arrays.AreEqual(enc, LmsPrivateKeyParameters.GetInstance(enc).GetEncoded()));
        }

        /**
         * An exhausted key refuses to issue further signing contexts with the dedicated exception type. The
         * index is claimed atomically inside GenerateLmsContext, so the final usage's signature must still
         * verify and the refusal must come from the claim itself.
         */
        [Test]
        public void TestKeyExhaustion()
        {
            byte[] seed = Hex.Decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
            byte[] I = Hex.Decode("d08fabd4a2091ff0a8cb4ed834e74534");
            byte[] msg = Hex.Decode("54686520656e756d65726174696f6e20696e2074686520436f6e737469747574");

            LmsPrivateKeyParameters privateKey = LmsTestUtilities.GenerateKey(
                LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4, 0, I, seed);
            LmsPublicKeyParameters publicKey = privateKey.GetPublicKey();

            LmsPrivateKeyParameters shard = privateKey.ExtractKeyShard(1);
            Assert.AreEqual(1, shard.GetUsagesRemaining());

            // the last usage still signs correctly...
            LmsSignature signature = LmsTestUtilities.GenerateSign(shard, msg);
            Assert.True(LmsTestUtilities.VerifySignature(publicKey, signature, msg));
            Assert.AreEqual(0, shard.GetUsagesRemaining());

            // ...and the next attempt is refused
            Assert.Throws<ExhaustedPrivateKeyException>(() => shard.GenerateLmsContext());

            // the parent key's own usage range is unaffected
            Assert.True(LmsTestUtilities.VerifySignature(publicKey, LmsTestUtilities.GenerateSign(privateKey, msg), msg));
        }

        /**
         * GetInstance(privEnc, pubEnc) cross-checks the cached root against the public key it is handed, which
         * catches a tree cache that is self-consistent but belongs to a different key. This check goes beyond
         * bc-java, which only applies it on the HSS entry point - the LMS path here is the one the PKCS#8
         * factory uses.
         */
        [Test]
        public void TestPrivateKeyCheckedAgainstSuppliedPublicKey()
        {
            byte[] seedA = Hex.Decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
            byte[] IA = Hex.Decode("d08fabd4a2091ff0a8cb4ed834e74534");
            byte[] seedB = Hex.Decode("a1c4696e2608035a886100d05cd99945eb3370731884a8235e2fb3d4d71f2547");
            byte[] IB = Hex.Decode("215f83b7ccb9acbcd08db97b0d04dc2b");

            LMSigParameters sigParams = LMSigParameters.lms_sha256_n32_h5;
            LMOtsParameters otsParams = LMOtsParameters.sha256_n32_w4;

            LmsPrivateKeyParameters keyA = LmsTestUtilities.GenerateKey(sigParams, otsParams, 0, IA, seedA);
            LmsPrivateKeyParameters keyB = LmsTestUtilities.GenerateKey(sigParams, otsParams, 0, IB, seedB);

            byte[] privA = keyA.GetEncoded();
            byte[] pubA = keyA.GetPublicKey().GetEncoded();
            byte[] pubB = keyB.GetPublicKey().GetEncoded();

            // matching pair: accepted, and the public key reported agrees
            LmsPrivateKeyParameters decoded = LmsPrivateKeyParameters.GetInstance(privA, pubA);
            Assert.True(Arrays.AreEqual(pubA, decoded.GetPublicKey().GetEncoded()));

            // another key's public key: refused
            var ex = Assert.Throws<IOException>(
                () => LmsPrivateKeyParameters.GetInstance(privA, pubB));
            Assert.True(ex.Message.StartsWith("LMS public key does not match the private key"));
        }

        /**
         * A private key encoding carrying an unknown LMS or LM-OTS type code is rejected with a clean parse
         * exception. The C# ParseByID helpers always did this - bc-java had to fix an NPE leak here - so this
         * pins the existing behaviour on the private key path.
         */
        [Test]
        public void TestMalformedPrivateKeyTypeCode()
        {
            byte[] seed = Hex.Decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
            byte[] I = Hex.Decode("d08fabd4a2091ff0a8cb4ed834e74534");

            byte[] unknownSigType = Composer.Compose()
                .U32Str(0)
                .U32Str(0x7fffffff) // bogus LMS type code
                .U32Str(LMOtsParameters.sha256_n32_w4.ID)
                .Bytes(I)
                .U32Str(0)
                .U32Str(32)
                .U32Str(seed.Length)
                .Bytes(seed)
                .Build();
            var ex1 = Assert.Throws<IOException>(
                () => LmsPrivateKeyParameters.GetInstance(unknownSigType));
            Assert.True(ex1.Message.StartsWith("unknown LMS type code"));

            byte[] unknownOtsType = Composer.Compose()
                .U32Str(0)
                .U32Str(LMSigParameters.lms_sha256_n32_h5.ID)
                .U32Str(0x7fffffff) // bogus LM-OTS type code
                .Bytes(I)
                .U32Str(0)
                .U32Str(32)
                .U32Str(seed.Length)
                .Bytes(seed)
                .Build();
            var ex2 = Assert.Throws<IOException>(
                () => LmsPrivateKeyParameters.GetInstance(unknownOtsType));
            Assert.True(ex2.Message.StartsWith("unknown LM-OTS type code"));
        }

        /*
         * BinaryReader.Read(byte[], int, int) makes a single Stream.Read call and may return fewer bytes than
         * asked for. The authentication path was read that way, so a short read left path nodes zero-filled
         * with no error: the signature parsed, re-encoded differently and failed to verify.
         */
        [Test]
        public void TestSignatureParseFromTrickleStream()
        {
            LMSigParameters sigParams = LMSigParameters.lms_sha256_n32_h5;
            LMOtsParameters otsParams = LMOtsParameters.sha256_n32_w4;
            byte[] seed = Hex.Decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
            byte[] I = Hex.Decode("d08fabd4a2091ff0a8cb4ed834e74534");

            LmsPrivateKeyParameters key = new LmsPrivateKeyParameters(sigParams, otsParams, 0, I, 1 << sigParams.H,
                seed);
            byte[] msg = Hex.Decode("48656c6c6f");
            byte[] encoded = LmsTestUtilities.GenerateSign(key, msg).GetEncoded();

            LmsSignature parsed = LmsSignature.GetInstance(new TrickleStream(encoded));

            Assert.True(Arrays.AreEqual(encoded, parsed.GetEncoded()), "short reads left the signature incomplete");
            Assert.True(LmsTestUtilities.VerifySignature(key.GetPublicKey(), parsed, msg));
        }

        // Hands out one byte per Read call, as a network or pipe stream is entitled to.
        private sealed class TrickleStream
            : MemoryStream
        {
            internal TrickleStream(byte[] buf)
                : base(buf, false)
            {
            }

            public override int Read(byte[] buffer, int offset, int count) =>
                base.Read(buffer, offset, System.Math.Min(count, 1));

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            public override int Read(Span<byte> buffer) =>
                base.Read(buffer.Slice(0, System.Math.Min(buffer.Length, 1)));
#endif
        }

        /*
         * p, ls and SigLen are derived from n and w (RFC 8554 Appendix B), so pin them to the published tables: RFC
         * 8554 sec. 4.1 for n=32 and SP 800-208 sec. 4 for n=24. An LM-OTS signature is u32str(type) || C ||
         * y[0..p-1], so SigLen is 4 + n + p*n; the eight n=24 sets used to carry LMS signature sizes instead - the
         * example rows of the additional-parameter-sets draft, w1 at h=25, w2 at h=20, w4 at h=10 and w8 at h=15 -
         * i.e. 5436/2940/1500/1020 where 4828/2452/1252/652 was meant.
         */
        [Test]
        public void TestOtsParameterTables()
        {
            LMOtsParameters[] all =
            {
                LMOtsParameters.sha256_n32_w1, LMOtsParameters.sha256_n32_w2,
                LMOtsParameters.sha256_n32_w4, LMOtsParameters.sha256_n32_w8,
                LMOtsParameters.sha256_n24_w1, LMOtsParameters.sha256_n24_w2,
                LMOtsParameters.sha256_n24_w4, LMOtsParameters.sha256_n24_w8,
                LMOtsParameters.shake256_n32_w1, LMOtsParameters.shake256_n32_w2,
                LMOtsParameters.shake256_n32_w4, LMOtsParameters.shake256_n32_w8,
                LMOtsParameters.shake256_n24_w1, LMOtsParameters.shake256_n24_w2,
                LMOtsParameters.shake256_n24_w4, LMOtsParameters.shake256_n24_w8,
            };
            int[] ws = { 1, 2, 4, 8 };
            int[] p32 = { 265, 133, 67, 34 }, ls32 = { 7, 6, 4, 0 };
            int[] p24 = { 200, 101, 51, 26 }, ls24 = { 8, 6, 4, 0 };

            for (int i = 0; i < all.Length; ++i)
            {
                LMOtsParameters ots = all[i];
                int col = i % 4;
                int n = (i / 4) % 2 == 0 ? 32 : 24;
                int p = n == 32 ? p32[col] : p24[col];
                int ls = n == 32 ? ls32[col] : ls24[col];
                string label = "LM-OTS type " + (i + 1);

                Assert.AreEqual(i + 1, ots.ID, label);
                Assert.AreEqual(n, ots.N, label);
                Assert.AreEqual(ws[col], ots.W, label);
                Assert.AreEqual(p, ots.P, label);
                Assert.AreEqual(ls, ots.Ls, label);
                Assert.AreEqual(4 + n + p * n, ots.SigLen, label);
            }

            // and against real signatures, one set per hash length and function
            LmsParameters[] samples =
            {
                new LmsParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                new LmsParameters(LMSigParameters.lms_sha256_n24_h5, LMOtsParameters.sha256_n24_w4),
                new LmsParameters(LMSigParameters.lms_shake256_n24_h5, LMOtsParameters.shake256_n24_w1),
            };
            byte[] seed = Hex.Decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
            byte[] I = Hex.Decode("d08fabd4a2091ff0a8cb4ed834e74534");
            byte[] msg = Hex.Decode("48656c6c6f");

            foreach (LmsParameters lms in samples)
            {
                LMSigParameters sigParams = lms.LMSigParameters;
                LMOtsParameters otsParams = lms.LMOtsParameters;

                LmsPrivateKeyParameters key = new LmsPrivateKeyParameters(sigParams, otsParams, 0, I,
                    1 << sigParams.H, seed);
                LmsSignature sig = LmsTestUtilities.GenerateSign(key, msg);

                Assert.AreEqual(otsParams.SigLen, sig.OtsSignature.GetEncoded().Length, "LM-OTS type " + otsParams.ID);

                // the LMS signature adds u32str(q), u32str(type) and the h path nodes (RFC 8554 sec. 5.4)
                Assert.AreEqual(4 + otsParams.SigLen + 4 + sigParams.H * sigParams.M, sig.GetEncoded().Length,
                    "LMS type " + sigParams.ID);
            }
        }

        /*
         * RFC 8554 sec. 5.4.2 steps 2g and 2i: a signature whose LMS typecode is not the public key's, or whose leaf
         * number lies outside the tree, is refused before any hashing rather than left to fail the final T1 compare
         * or to run off the end of the path.
         */
        [Test]
        public void TestVerifyRejectsWrongTypeAndLeafNumber()
        {
            LMSigParameters sigParams = LMSigParameters.lms_sha256_n32_h5;
            LMOtsParameters otsParams = LMOtsParameters.sha256_n32_w4;
            byte[] seed = Hex.Decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
            byte[] I = Hex.Decode("d08fabd4a2091ff0a8cb4ed834e74534");
            byte[] msg = Hex.Decode("48656c6c6f");

            LmsPrivateKeyParameters key = new LmsPrivateKeyParameters(sigParams, otsParams, 0, I, 1 << sigParams.H,
                seed);
            LmsPublicKeyParameters pub = key.GetPublicKey();
            LmsSignature sig = LmsTestUtilities.GenerateSign(key, msg);
            Assert.True(LmsTestUtilities.VerifySignature(pub, sig, msg));

            // 2g: same hash function, different height
            LmsSignature wrongType = new LmsSignature(sig.Q, sig.OtsSignature, LMSigParameters.lms_sha256_n32_h10,
                sig.Y);
            var ex = Assert.Throws<ArgumentException>(() => LmsTestUtilities.VerifySignature(pub, wrongType, msg));
            Assert.True(ex.Message.Contains("lms type"));

            // 2i: at and beyond 2^h, and negative
            foreach (int q in new int[] { 1 << sigParams.H, -1, int.MaxValue })
            {
                LmsSignature wrongQ = new LmsSignature(q, sig.OtsSignature, sig.SigParameters, sig.Y);
                ex = Assert.Throws<ArgumentException>(() => LmsTestUtilities.VerifySignature(pub, wrongQ, msg));
                Assert.True(ex.Message.Contains("leaf number"));
            }

            // the signer reports a refusal as a failed verification
            LmsSigner verifier = new LmsSigner();
            verifier.Init(false, pub);
            LmsSignature qTooLarge = new LmsSignature(1 << sigParams.H, sig.OtsSignature, sig.SigParameters, sig.Y);
            Assert.False(verifier.VerifySignature(msg, qTooLarge.GetEncoded()));
            Assert.True(verifier.VerifySignature(msg, sig.GetEncoded()));
        }

        /// <summary>
        /// The private key retains the authentication path of the last one-time key used and advances it to the
        /// next, sharing what the two have in common; the shared prefix and the swap at the divergence level are
        /// exercised at every level by signing a whole height-5 tree in order. A wrong node anywhere in a path makes
        /// the signature fail to verify. (A guard for the retained path rather than a regression test: a key that
        /// rebuilt every path from scratch would pass it too.)
        /// </summary>
        [Test]
        public void RetainedPathCoversEveryDivergenceDepth()
        {
            SignInOrderAndVerify(LMSigParameters.lms_sha256_n32_h5, 1 << 5);
            SignInOrderAndVerify(LMSigParameters.lms_sha256_n32_h10, 70); // past the pinned top's level
        }

        private static void SignInOrderAndVerify(LMSigParameters sigParams, int count)
        {
            LmsPrivateKeyParameters key = GenerateKey(sigParams, LMOtsParameters.sha256_n32_w8);
            LmsPublicKeyParameters pub = key.GetPublicKey();
            byte[] msg = Strings.ToByteArray("retained path");

            for (int i = 0; i < count; ++i)
            {
                byte[] sig = Sign(key, msg);
                Assert.AreEqual(i, LmsSignature.GetInstance(sig).Q);
                Assert.True(Verify(pub, sig, msg), "signature " + i + " of " + sigParams.H + " did not verify");
            }
        }

        /// <summary>
        /// A shard inherits the retained path of its parent and the parent keeps signing after a jump over the
        /// shard's range; a later shard makes a jump into the other half of the tree.
        /// </summary>
        [Test]
        public void RetainedPathSurvivesShardsAndJumps()
        {
            LmsPrivateKeyParameters key = GenerateKey(LMSigParameters.lms_sha256_n32_h10, LMOtsParameters.sha256_n32_w8);
            LmsPublicKeyParameters pub = key.GetPublicKey();
            byte[] msg = Strings.ToByteArray("shards and jumps");
            var seen = new HashSet<int>();

            for (int i = 0; i < 4; ++i)
            {
                SignVerifyAndRecord(key, pub, msg, seen);
            }

            LmsPrivateKeyParameters shard = key.ExtractKeyShard(4);
            for (int i = 0; i < 4; ++i)
            {
                SignVerifyAndRecord(shard, pub, msg, seen);
            }
            Assert.Throws<ExhaustedPrivateKeyException>(() => Sign(shard, msg));

            for (int i = 0; i < 4; ++i)
            {
                SignVerifyAndRecord(key, pub, msg, seen);
            }

            LmsPrivateKeyParameters skip = key.ExtractKeyShard(500); // jump past the midpoint
            Assert.AreEqual(512, key.GetIndex());
            for (int i = 0; i < 3; ++i)
            {
                SignVerifyAndRecord(key, pub, msg, seen);
            }
            for (int i = 0; i < 3; ++i)
            {
                SignVerifyAndRecord(skip, pub, msg, seen);
            }

            Assert.AreEqual(18, seen.Count, "a one-time key was used twice");
        }

        private static void SignVerifyAndRecord(LmsPrivateKeyParameters key, LmsPublicKeyParameters pub, byte[] msg,
            HashSet<int> seen)
        {
            int q = key.GetIndex();
            byte[] sig = Sign(key, msg);
            Assert.AreEqual(q, LmsSignature.GetInstance(sig).Q);
            Assert.True(Verify(pub, sig, msg), "signature with q = " + q + " did not verify");
            Assert.True(seen.Add(q));
        }

        /// <summary>
        /// Several signers over one key share its retained path: every signature they produce verifies and no
        /// one-time key is used twice.
        /// </summary>
        [Test]
        public void ParallelSignersShareOneKey()
        {
            const int Threads = 4, PerThread = 64;

            LmsPrivateKeyParameters key = GenerateKey(LMSigParameters.lms_sha256_n32_h10, LMOtsParameters.sha256_n32_w8);
            LmsPublicKeyParameters pub = key.GetPublicKey();
            byte[] msg = Strings.ToByteArray("parallel signers");

            byte[][] sigs = new byte[Threads * PerThread][];
            Exception[] failures = new Exception[Threads];
            Thread[] threads = new Thread[Threads];

            for (int t = 0; t < Threads; ++t)
            {
                int thread = t;
                threads[t] = new Thread(() =>
                {
                    try
                    {
                        LmsSigner signer = new LmsSigner();
                        signer.Init(true, key);
                        for (int i = 0; i < PerThread; ++i)
                        {
                            sigs[thread * PerThread + i] = signer.GenerateSignature(msg);
                        }
                    }
                    catch (Exception e)
                    {
                        failures[thread] = e;
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

            for (int t = 0; t < Threads; ++t)
            {
                Assert.Null(failures[t], "signer " + t + " failed: " + failures[t]);
            }
            Assert.AreEqual(Threads * PerThread, key.GetIndex());

            var seen = new HashSet<int>();
            foreach (byte[] sig in sigs)
            {
                Assert.True(Verify(pub, sig, msg));
                Assert.True(seen.Add(LmsSignature.GetInstance(sig).Q), "a one-time key was used twice");
            }
        }

        private static LmsPrivateKeyParameters GenerateKey(LMSigParameters sigParams, LMOtsParameters otsParams)
        {
            SecureRandom random = new SecureRandom();
            byte[] I = SecureRandom.GetNextBytes(random, 16);
            byte[] seed = SecureRandom.GetNextBytes(random, 32);
            return LmsTestUtilities.GenerateKey(sigParams, otsParams, 0, I, seed);
        }

        private static int ReadU32(byte[] buf, int off) =>
            (buf[off] << 24) | (buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3];

        private static void WriteU32(int x, byte[] bs, int off)
        {
            uint n = (uint)x;
            bs[off] = (byte)(n >> 24);
            bs[off + 1] = (byte)(n >> 16);
            bs[off + 2] = (byte)(n >> 8);
            bs[off + 3] = (byte)n;
        }

        private static byte[] Sign(LmsPrivateKeyParameters key, byte[] message)
        {
            LmsSigner signer = new LmsSigner();
            signer.Init(true, key);
            return signer.GenerateSignature(message);
        }

        private static bool Verify(LmsPublicKeyParameters key, byte[] signature, byte[] message)
        {
            LmsSigner signer = new LmsSigner();
            signer.Init(false, key);
            return signer.VerifySignature(message, signature);
        }
    }
}
