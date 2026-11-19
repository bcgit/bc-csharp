using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Pqc.Asn1;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>
    /// The versioned binary form the BDS traversal state is carried in, in the raw private key encoding and in the
    /// [1] bdsState alternative of the legacy PrivateKeyInfo form.
    /// </summary>
    /// <remarks>
    /// bc-java also reads state that Java object serialization wrote, in the raw encoding and in the [0] bdsState
    /// alternative; this port does not (see <see cref="XmssUtilities.Deserialize"/>). The two Java methods that read
    /// such a state, <c>testXmssReadsLegacyJavaSerializedState</c> and its XMSS^MT twin, are ported as the refusal
    /// of one, and the two that read the [0] alternative check that the alternative itself is still accepted, with
    /// the codec form inside it, and that a Java-serialized state inside it is refused.
    /// </remarks>
    [TestFixture]
    public class XmssStateEncodingTests
    {
        private const int BdsStateMagic = 0x42445300;
        private const int BdsStateMapMagic = 0x42444d00;
        private const int StateVersion = 1;

        [Test]
        public void TestXmssUsesBinaryStateEncoding()
        {
            XmssParameters parameters = new XmssParameters(4, new Sha256Digest());
            AsymmetricCipherKeyPair kp = GenerateXmssKeyPair(parameters);
            XmssPrivateKeyParameters privateKey = (XmssPrivateKeyParameters)kp.Private;

            byte[] encoding = privateKey.GetEncoded();
            int stateOffset = 4 + 4 * parameters.TreeDigestSize;
            Assert.AreEqual(BdsStateMagic, (int)Pack.BE_To_UInt32(encoding, stateOffset));
            Assert.AreEqual(StateVersion, (int)Pack.BE_To_UInt32(encoding, stateOffset + 4));

            XmssPrivateKeyParameters recovered = new XmssPrivateKeyParameters.Builder(parameters)
                .WithPrivateKey(encoding).Build();
            AssertXmssSigns(recovered, kp);
        }

        [Test]
        public void TestXmssMtUsesBinaryStateEncoding()
        {
            XmssMTParameters parameters = new XmssMTParameters(4, 2, new Sha256Digest());
            AsymmetricCipherKeyPair kp = GenerateXmssMtKeyPair(parameters);
            XmssMTPrivateKeyParameters privateKey = (XmssMTPrivateKeyParameters)kp.Private;

            byte[] encoding = privateKey.GetEncoded();
            int stateOffset = (parameters.Height + 7) / 8 + 4 * parameters.TreeDigestSize;
            Assert.AreEqual(BdsStateMapMagic, (int)Pack.BE_To_UInt32(encoding, stateOffset));
            Assert.AreEqual(StateVersion, (int)Pack.BE_To_UInt32(encoding, stateOffset + 4));

            XmssMTPrivateKeyParameters recovered = new XmssMTPrivateKeyParameters.Builder(parameters)
                .WithPrivateKey(encoding).Build();
            AssertXmssMtSigns(recovered, kp);
        }

        /// <summary>A raw encoding whose state Java object serialization wrote is refused, not read.</summary>
        [Test]
        public void TestXmssReadsLegacyJavaSerializedState()
        {
            XmssParameters parameters = new XmssParameters(4, new Sha256Digest());
            XmssPrivateKeyParameters privateKey = (XmssPrivateKeyParameters)GenerateXmssKeyPair(parameters).Private;
            byte[] currentEncoding = privateKey.GetEncoded();
            int stateOffset = 4 + 4 * parameters.TreeDigestSize;
            byte[] legacyEncoding = Arrays.Concatenate(Arrays.CopyOfRange(currentEncoding, 0, stateOffset),
                CraftedLegacyStateTests.CraftedBds());

            ArgumentException e = Assert.Throws<ArgumentException>(() => new XmssPrivateKeyParameters.Builder(
                parameters).WithPrivateKey(legacyEncoding).Build());
            Assert.AreEqual("unrecognized BDS state encoding", e.Message);
            Assert.IsInstanceOf<IOException>(e.InnerException);
        }

        /// <summary>The XMSS^MT twin of <see cref="TestXmssReadsLegacyJavaSerializedState"/>.</summary>
        [Test]
        public void TestXmssMtReadsLegacyJavaSerializedState()
        {
            XmssMTParameters parameters = new XmssMTParameters(4, 2, new Sha256Digest());
            XmssMTPrivateKeyParameters privateKey =
                (XmssMTPrivateKeyParameters)GenerateXmssMtKeyPair(parameters).Private;
            byte[] currentEncoding = privateKey.GetEncoded();
            int stateOffset = (parameters.Height + 7) / 8 + 4 * parameters.TreeDigestSize;
            byte[] legacyEncoding = Arrays.Concatenate(Arrays.CopyOfRange(currentEncoding, 0, stateOffset),
                CraftedLegacyStateTests.CraftedBdsStateMap());

            ArgumentException e = Assert.Throws<ArgumentException>(() => new XmssMTPrivateKeyParameters.Builder(
                parameters).WithPrivateKey(legacyEncoding).Build());
            Assert.AreEqual("unrecognized BDS state encoding", e.Message);
            Assert.IsInstanceOf<IOException>(e.InnerException);
        }

        /// <summary>
        /// The encoded BDS state carries a checksum over itself, bound to the owning key's public seed, and a key whose
        /// state does not match it is refused. This is an error-detecting code against bit rot, partial writes and
        /// truncated records, not integrity protection: anyone able to rewrite the stored key recomputes it
        /// (bc-java github #2414).
        /// </summary>
        [Test]
        public void TestStateChecksumRejectsCorruption()
        {
            XmssParameters parameters = new XmssParameters(4, new Sha256Digest());
            int n = parameters.TreeDigestSize;
            AsymmetricCipherKeyPair kp = GenerateXmssKeyPair(parameters);
            byte[] encoding = ((XmssPrivateKeyParameters)kp.Private).GetEncoded();
            int stateOffset = 4 + 4 * n;

            // past the 8-byte magic and version it is the checksum that catches a corruption
            for (int i = stateOffset + 8; i != encoding.Length; i++)
            {
                byte[] corrupt = Arrays.Clone(encoding);
                corrupt[i] ^= 0x01;
                ArgumentException e = Assert.Throws<ArgumentException>(
                    () => new XmssPrivateKeyParameters.Builder(parameters).WithPrivateKey(corrupt).Build(),
                    "no exception on corrupt state byte " + i);
                Assert.AreEqual("BDS state checksum does not match", e.Message, "byte " + i);
            }

            for (int i = stateOffset; i != stateOffset + 8; i++)
            {
                byte[] corrupt = Arrays.Clone(encoding);
                corrupt[i] ^= 0x01;
                Assert.Throws<ArgumentException>(
                    () => new XmssPrivateKeyParameters.Builder(parameters).WithPrivateKey(corrupt).Build(),
                    "no exception on corrupt state header byte " + i);
            }

            // a state transplanted from another key of the same parameters is caught by the seed binding, even though
            // it is internally consistent and brings its own matching root
            byte[] other = ((XmssPrivateKeyParameters)GenerateXmssKeyPair(parameters).Private).GetEncoded();
            Assert.AreEqual(encoding.Length, other.Length);
            byte[] transplant = Arrays.Clone(encoding);
            Array.Copy(other, 4 + 3 * n, transplant, 4 + 3 * n, other.Length - (4 + 3 * n));
            ArgumentException te = Assert.Throws<ArgumentException>(
                () => new XmssPrivateKeyParameters.Builder(parameters).WithPrivateKey(transplant).Build(),
                "state from a different key accepted");
            Assert.AreEqual("BDS state checksum does not match", te.Message);

            // and the untouched encoding still decodes and signs verifiably
            XmssPrivateKeyParameters decoded =
                new XmssPrivateKeyParameters.Builder(parameters).WithPrivateKey(encoding).Build();
            XmssSigner signer = new XmssSigner();
            signer.Init(true, decoded);
            byte[] sig = XmssHarnessTests.Sign(signer, Strings.ToByteArray("message"));
            XmssSigner verifier = new XmssSigner();
            verifier.Init(false, kp.Public);
            Assert.IsTrue(XmssHarnessTests.Verify(verifier, Strings.ToByteArray("message"), sig));
        }

        private static void RefreshStateChecksum(byte[] encoding, XmssParameters parameters)
        {
            int n = parameters.TreeDigestSize;
            int publicSeedOffset = 4 + 2 * n;
            int stateOffset = 4 + 4 * n;
            int bodyEnd = encoding.Length - 32;

            Sha256Digest digest = new Sha256Digest();
            digest.BlockUpdate(encoding, publicSeedOffset, n);
            digest.BlockUpdate(encoding, stateOffset, bodyEnd - stateOffset);
            digest.DoFinal(encoding, bodyEnd);
        }

        [Test]
        public void TestStateCollectionCountIsBoundedBeforeAllocation()
        {
            XmssParameters parameters = new XmssParameters(4, new Sha256Digest());
            AsymmetricCipherKeyPair kp = GenerateXmssKeyPair(parameters);
            byte[] encoding = ((XmssPrivateKeyParameters)kp.Private).GetEncoded();
            int stateOffset = 4 + 4 * parameters.TreeDigestSize;
            int authenticationPathCountOffset = stateOffset + 8 + 4 * 4 + 1 + 1 + 4 + 4 + parameters.TreeDigestSize;
            Pack.UInt32_To_BE((uint)(parameters.Height + 1), encoding, authenticationPathCountOffset);
            // the checksum is verified before anything is parsed, so a crafted encoding carries a valid one to reach
            // the allocation bounds at all: it detects corruption, it is not authentication (bc-java github #2414)
            RefreshStateChecksum(encoding, parameters);

            ArgumentException e = Assert.Throws<ArgumentException>(
                () => new XmssPrivateKeyParameters.Builder(parameters).WithPrivateKey(encoding).Build(),
                "oversized BDS authentication path accepted");
            Assert.AreEqual("BDS authentication path size out of bounds", e.Message);
        }

        [Test]
        public void TestXmssBuilderRejectsStateForDifferentParameters()
        {
            XmssParameters parameters = new XmssParameters(4, new Sha256Digest());
            XmssPrivateKeyParameters privateKey = (XmssPrivateKeyParameters)GenerateXmssKeyPair(parameters).Private;
            XmssParameters mismatchedParams = new XmssParameters(6, new Sha256Digest());

            ArgumentException e = Assert.Throws<ArgumentException>(
                () => new XmssPrivateKeyParameters.Builder(mismatchedParams)
                    .WithIndex(privateKey.Index)
                    .WithSecretKeySeed(privateKey.GetSecretKeySeed())
                    .WithSecretKeyPrf(privateKey.GetSecretKeyPrf())
                    .WithPublicSeed(privateKey.GetPublicSeed())
                    .WithRoot(privateKey.GetRoot())
                    .WithBdsState(privateKey.GetBdsState())
                    .Build(),
                "XMSS BDS state for different parameters accepted");
            Assert.AreEqual("BDS state does not match XMSS parameters", e.Message);
        }

        [Test]
        public void TestXmssMtBuilderRejectsStateForDifferentParameters()
        {
            XmssMTParameters parameters = new XmssMTParameters(4, 2, new Sha256Digest());
            XmssMTPrivateKeyParameters privateKey =
                (XmssMTPrivateKeyParameters)GenerateXmssMtKeyPair(parameters).Private;
            XmssMTParameters mismatchedParams = new XmssMTParameters(6, 2, new Sha256Digest());

            ArgumentException e = Assert.Throws<ArgumentException>(
                () => new XmssMTPrivateKeyParameters.Builder(mismatchedParams)
                    .WithIndex(privateKey.Index)
                    .WithSecretKeySeed(privateKey.GetSecretKeySeed())
                    .WithSecretKeyPrf(privateKey.GetSecretKeyPrf())
                    .WithPublicSeed(privateKey.GetPublicSeed())
                    .WithRoot(privateKey.GetRoot())
                    .WithBdsState(privateKey.GetBdsState())
                    .Build(),
                "XMSSMT BDS state for different parameters accepted");
            Assert.AreEqual("BDS state does not match XMSS parameters", e.Message);
        }

        [Test]
        public void TestXmssStateRoundTripsAcrossTreeUpdates()
        {
            XmssParameters parameters = new XmssParameters(4, new Sha256Digest());
            AsymmetricCipherKeyPair kp = GenerateXmssKeyPair(parameters);
            XmssPrivateKeyParameters privateKey = (XmssPrivateKeyParameters)kp.Private;

            for (int i = 0; i < 16; i++)
            {
                byte[] encoding = privateKey.GetEncoded();
                privateKey = new XmssPrivateKeyParameters.Builder(parameters).WithPrivateKey(encoding).Build();

                byte[] message = new byte[]{ (byte)i };
                XmssSigner signer = new XmssSigner();
                signer.Init(true, privateKey);
                byte[] signature = XmssHarnessTests.Sign(signer, message);

                XmssSigner verifier = new XmssSigner();
                verifier.Init(false, kp.Public);
                Assert.IsTrue(XmssHarnessTests.Verify(verifier, message, signature), "signature at index " + i);
                privateKey = (XmssPrivateKeyParameters)signer.GetUpdatedPrivateKey();
            }
        }

        [Test]
        public void TestXmssMtStateRoundTripsAcrossTreeUpdates()
        {
            XmssMTParameters parameters = new XmssMTParameters(4, 2, new Sha256Digest());
            AsymmetricCipherKeyPair kp = GenerateXmssMtKeyPair(parameters);
            XmssMTPrivateKeyParameters privateKey = (XmssMTPrivateKeyParameters)kp.Private;

            for (int i = 0; i < 16; i++)
            {
                byte[] encoding = privateKey.GetEncoded();
                privateKey = new XmssMTPrivateKeyParameters.Builder(parameters).WithPrivateKey(encoding).Build();

                byte[] message = new byte[]{ (byte)i };
                XmssMTSigner signer = new XmssMTSigner();
                signer.Init(true, privateKey);
                byte[] signature = XmssHarnessTests.Sign(signer, message);

                XmssMTSigner verifier = new XmssMTSigner();
                verifier.Init(false, kp.Public);
                Assert.IsTrue(XmssHarnessTests.Verify(verifier, message, signature), "signature at index " + i);
                privateKey = (XmssMTPrivateKeyParameters)signer.GetUpdatedPrivateKey();
            }
        }

        [Test]
        public void TestXmssPrivateKeyInfoUsesBinaryBdsStateChoice()
        {
            XmssParameters parameters = new XmssParameters(4, new Sha256Digest());
            AsymmetricCipherKeyPair kp = GenerateXmssKeyPair(parameters);
            XmssPrivateKeyParameters privateKey = (XmssPrivateKeyParameters)kp.Private;

            PrivateKeyInfo keyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
            Assert.AreEqual(PqcObjectIdentifiers.xmss, keyInfo.PrivateKeyAlgorithm.Algorithm);

            Asn1Sequence seq = Asn1Sequence.GetInstance(keyInfo.ParsePrivateKey());
            Assert.AreEqual(1, Asn1TaggedObject.GetInstance(seq[2]).TagNo);
            Assert.IsTrue(XmssPrivateKey.GetInstance(seq).HasBinaryBdsState);

            XmssPrivateKeyParameters restored =
                (XmssPrivateKeyParameters)PrivateKeyFactory.CreateKey(keyInfo.GetEncoded());
            AssertXmssSigns(restored, kp);
        }

        /// <summary>
        /// The legacy [0] bdsState alternative, which is accepted on parsing but no longer written: with the codec form
        /// inside it the key reads back and signs; with a Java-serialized state inside it, it is refused.
        /// </summary>
        [Test]
        public void TestXmssPrivateKeyAcceptsLegacyBdsStateChoice()
        {
            XmssParameters parameters = new XmssParameters(4, new Sha256Digest());
            AsymmetricCipherKeyPair kp = GenerateXmssKeyPair(parameters);
            XmssPrivateKeyParameters privateKey = (XmssPrivateKeyParameters)kp.Private;

            PrivateKeyInfo keyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
            Asn1Sequence seq = Asn1Sequence.GetInstance(keyInfo.ParsePrivateKey());

            // BC no longer generates the legacy alternative, so build the [0] form by hand
            Asn1Sequence legacy = LegacyBdsStateSequence(seq, XmssPrivateKey.GetInstance(seq).GetBdsState());
            PrivateKeyInfo legacyInfo = new PrivateKeyInfo(keyInfo.PrivateKeyAlgorithm, legacy);

            Asn1Sequence legacySeq = Asn1Sequence.GetInstance(legacyInfo.ParsePrivateKey());
            Assert.AreEqual(0, Asn1TaggedObject.GetInstance(legacySeq[2]).TagNo);
            Assert.IsFalse(XmssPrivateKey.GetInstance(legacySeq).HasBinaryBdsState);

            XmssPrivateKeyParameters restored =
                (XmssPrivateKeyParameters)PrivateKeyFactory.CreateKey(legacyInfo.GetEncoded());
            AssertXmssSigns(restored, kp);

            PrivateKeyInfo serializedInfo = new PrivateKeyInfo(keyInfo.PrivateKeyAlgorithm,
                LegacyBdsStateSequence(seq, CraftedLegacyStateTests.CraftedBds()));
            ArgumentException e = Assert.Throws<ArgumentException>(
                () => PrivateKeyFactory.CreateKey(serializedInfo.GetEncoded()));
            Assert.AreEqual("unrecognized BDS state encoding", e.Message);
        }

        [Test]
        public void TestXmssPrivateKeyRejectsUnknownBdsStateChoice()
        {
            XmssParameters parameters = new XmssParameters(4, new Sha256Digest());
            AsymmetricCipherKeyPair kp = GenerateXmssKeyPair(parameters);

            PrivateKeyInfo keyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(kp.Private);
            Asn1Sequence seq = Asn1Sequence.GetInstance(keyInfo.ParsePrivateKey());

            Asn1EncodableVector v = new Asn1EncodableVector();
            v.Add(seq[0]);
            v.Add(seq[1]);
            v.Add(new DerTaggedObject(true, 2, new DerOctetString(XmssPrivateKey.GetInstance(seq).GetBdsState())));

            ArgumentException e = Assert.Throws<ArgumentException>(
                () => XmssPrivateKey.GetInstance(new DerSequence(v)), "unknown bdsState choice accepted");
            Assert.AreEqual("unknown bdsState choice in XMSSPrivateKey", e.Message);
        }

        [Test]
        public void TestXmssMtPrivateKeyInfoUsesBinaryBdsStateChoice()
        {
            XmssMTParameters parameters = new XmssMTParameters(4, 2, new Sha256Digest());
            AsymmetricCipherKeyPair kp = GenerateXmssMtKeyPair(parameters);
            XmssMTPrivateKeyParameters privateKey = (XmssMTPrivateKeyParameters)kp.Private;

            PrivateKeyInfo keyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
            Assert.AreEqual(PqcObjectIdentifiers.xmss_mt, keyInfo.PrivateKeyAlgorithm.Algorithm);

            Asn1Sequence seq = Asn1Sequence.GetInstance(keyInfo.ParsePrivateKey());
            Assert.AreEqual(1, Asn1TaggedObject.GetInstance(seq[2]).TagNo);
            Assert.IsTrue(XmssMTPrivateKey.GetInstance(seq).HasBinaryBdsState);

            XmssMTPrivateKeyParameters restored =
                (XmssMTPrivateKeyParameters)PrivateKeyFactory.CreateKey(keyInfo.GetEncoded());
            AssertXmssMtSigns(restored, kp);
        }

        /// <summary>The XMSS^MT twin of <see cref="TestXmssPrivateKeyAcceptsLegacyBdsStateChoice"/>.</summary>
        [Test]
        public void TestXmssMtPrivateKeyAcceptsLegacyBdsStateChoice()
        {
            XmssMTParameters parameters = new XmssMTParameters(4, 2, new Sha256Digest());
            AsymmetricCipherKeyPair kp = GenerateXmssMtKeyPair(parameters);
            XmssMTPrivateKeyParameters privateKey = (XmssMTPrivateKeyParameters)kp.Private;

            PrivateKeyInfo keyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
            Asn1Sequence seq = Asn1Sequence.GetInstance(keyInfo.ParsePrivateKey());

            Asn1Sequence legacy = LegacyBdsStateSequence(seq, XmssMTPrivateKey.GetInstance(seq).GetBdsState());
            PrivateKeyInfo legacyInfo = new PrivateKeyInfo(keyInfo.PrivateKeyAlgorithm, legacy);

            Asn1Sequence legacySeq = Asn1Sequence.GetInstance(legacyInfo.ParsePrivateKey());
            Assert.AreEqual(0, Asn1TaggedObject.GetInstance(legacySeq[2]).TagNo);
            Assert.IsFalse(XmssMTPrivateKey.GetInstance(legacySeq).HasBinaryBdsState);

            XmssMTPrivateKeyParameters restored =
                (XmssMTPrivateKeyParameters)PrivateKeyFactory.CreateKey(legacyInfo.GetEncoded());
            AssertXmssMtSigns(restored, kp);

            PrivateKeyInfo serializedInfo = new PrivateKeyInfo(keyInfo.PrivateKeyAlgorithm,
                LegacyBdsStateSequence(seq, CraftedLegacyStateTests.CraftedBdsStateMap()));
            ArgumentException e = Assert.Throws<ArgumentException>(
                () => PrivateKeyFactory.CreateKey(serializedInfo.GetEncoded()));
            Assert.AreEqual("unrecognized BDS state encoding", e.Message);
        }

        [Test]
        public void TestXmssMtPrivateKeyRejectsUnknownBdsStateChoice()
        {
            XmssMTParameters parameters = new XmssMTParameters(4, 2, new Sha256Digest());
            AsymmetricCipherKeyPair kp = GenerateXmssMtKeyPair(parameters);

            PrivateKeyInfo keyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(kp.Private);
            Asn1Sequence seq = Asn1Sequence.GetInstance(keyInfo.ParsePrivateKey());

            Asn1EncodableVector v = new Asn1EncodableVector();
            v.Add(seq[0]);
            v.Add(seq[1]);
            v.Add(new DerTaggedObject(true, 2, new DerOctetString(XmssMTPrivateKey.GetInstance(seq).GetBdsState())));

            ArgumentException e = Assert.Throws<ArgumentException>(
                () => XmssMTPrivateKey.GetInstance(new DerSequence(v)), "unknown bdsState choice accepted");
            Assert.AreEqual("unknown bdsState choice in XMSSMTPrivateKey", e.Message);
        }

        private static AsymmetricCipherKeyPair GenerateXmssKeyPair(XmssParameters parameters)
        {
            XmssKeyPairGenerator generator = new XmssKeyPairGenerator();
            generator.Init(new XmssKeyGenerationParameters(new SecureRandom(), parameters));
            return generator.GenerateKeyPair();
        }

        private static AsymmetricCipherKeyPair GenerateXmssMtKeyPair(XmssMTParameters parameters)
        {
            XmssMTKeyPairGenerator generator = new XmssMTKeyPairGenerator();
            generator.Init(new XmssMTKeyGenerationParameters(new SecureRandom(), parameters));
            return generator.GenerateKeyPair();
        }

        /// <summary>
        /// An XmssPrivateKey / XmssMTPrivateKey sequence with the bdsState carried in the legacy [0] alternative,
        /// which is accepted on parsing but no longer generated.
        /// </summary>
        private static Asn1Sequence LegacyBdsStateSequence(Asn1Sequence seq, byte[] state)
        {
            Asn1EncodableVector v = new Asn1EncodableVector();
            v.Add(seq[0]);
            v.Add(seq[1]);
            v.Add(new DerTaggedObject(true, 0, new DerOctetString(state)));
            return new DerSequence(v);
        }

        private static void AssertXmssSigns(XmssPrivateKeyParameters privateKey, AsymmetricCipherKeyPair kp)
        {
            byte[] message = new byte[]{ 1, 2, 3, 4 };
            XmssSigner signer = new XmssSigner();
            signer.Init(true, privateKey);
            byte[] signature = XmssHarnessTests.Sign(signer, message);

            XmssSigner verifier = new XmssSigner();
            verifier.Init(false, kp.Public);
            Assert.IsTrue(XmssHarnessTests.Verify(verifier, message, signature));
        }

        private static void AssertXmssMtSigns(XmssMTPrivateKeyParameters privateKey, AsymmetricCipherKeyPair kp)
        {
            byte[] message = new byte[]{ 1, 2, 3, 4 };
            XmssMTSigner signer = new XmssMTSigner();
            signer.Init(true, privateKey);
            byte[] signature = XmssHarnessTests.Sign(signer, message);

            XmssMTSigner verifier = new XmssMTSigner();
            verifier.Init(false, kp.Public);
            Assert.IsTrue(XmssHarnessTests.Verify(verifier, message, signature));
        }
    }
}
