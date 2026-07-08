using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Bcpg.Sig;

namespace Org.BouncyCastle.Bcpg.Tests
{
    [TestFixture]
    public class SignatureSubpacketsTest
    {
        /// <summary>
        /// Confirm that truncated subpackets are correctly rejected.
        /// </summary>
        /// <remarks>
        /// The Features, TrustSignature, SignatureTarget, RevocationKey and RevocationReason subpackets index a fixed
        /// offset of their body from an accessor (e.g. <see cref="Features.GetFeatures"/> reads <c>Data[0]</c>). A
        /// truncated body (empty, or a single octet for the two-octet subpackets) must therefore be rejected when the
        /// subpacket is parsed, with an <see cref="ArgumentException"/>, rather than decoding cleanly and throwing an
        /// <see cref="IndexOutOfRangeException"/> later when an accessor is read.
        /// </remarks>
        [Test]
        public void TruncatedSubpacketsRejected()
        {
            // getFeatures() / supportsFeature() read data[0]
            CheckConstructionRejected("Features", new byte[0]);

            // getDepth() reads data[0], getTrustAmount() reads data[1]
            CheckConstructionRejected("TrustSignature", new byte[0]);
            CheckConstructionRejected("TrustSignature", new byte[1]);

            // getPublicKeyAlgorithm() reads data[0], getHashAlgorithm() reads data[1]
            CheckConstructionRejected("SignatureTarget", new byte[0]);
            CheckConstructionRejected("SignatureTarget", new byte[1]);

            // getSignatureClass() reads data[0], getAlgorithm() reads data[1]
            CheckConstructionRejected("RevocationKey", new byte[0]);
            CheckConstructionRejected("RevocationKey", new byte[1]);

            // getRevocationReason() reads data[0]
            CheckConstructionRejected("RevocationReason", new byte[0]);

            // getNotationName()/getNotationValueBytes() index the 8-octet header (flags[4],
            // nameLength[2], valueLength[2]) then the name and value, so a body shorter than
            // 8 + nameLength + valueLength must be rejected. The guard previously counted only a
            // 4-octet header, so a body that declared more name/value than it carried slipped past
            // and overran later in an accessor (github #2346).
            CheckConstructionRejected("NotationData", new byte[0]);            // shorter than the 8-octet header
            CheckConstructionRejected("NotationData", new byte[7]);            // still shorter than the header
            CheckConstructionRejected("NotationData", NotationBody(2, 2, 0));  // header declares 4 body octets, none present
            CheckConstructionRejected("NotationData", NotationBody(1, 0, 0));  // header declares a 1-octet name, none present

            // the truncated body is reachable from the wire, not just the API: a subpacket whose
            // length field is 1 carries only its type octet (an empty body), which the parser now
            // rejects with a MalformedPacketException wrapping the constructor's exception.
            CheckWireDecodeRejected(SignatureSubpacketTag.Features, 1);
            CheckWireDecodeRejected(SignatureSubpacketTag.TrustSig, 2);
            CheckWireDecodeRejected(SignatureSubpacketTag.NotationData, NotationBody(2, 2, 0));
        }

        /// <summary>A body exactly at the minimum length must still be accepted, with working accessors.</summary>
        [Test]
        public void MinimalBodiesAccepted()
        {
            Features features = new Features(false, false, new byte[] { Features.FEATURE_SEIPD_V2 });
            Assert.AreEqual(Features.FEATURE_SEIPD_V2, features.GetFeatures(), "Features body not preserved");
            Assert.True(features.SupportsFeature(Features.FEATURE_SEIPD_V2), "Features.supportsFeature mismatch");

            TrustSignature trust = new TrustSignature(false, false, new byte[]{ 2, (byte)120 });
            Assert.AreEqual(2, trust.Depth, "TrustSignature depth mismatch");
            Assert.AreEqual(120, trust.TrustAmount, "TrustSignature trust-amount mismatch");

            SignatureTarget target = new SignatureTarget(false, false, new byte[]{ 1, 8 });
            Assert.AreEqual(1, target.PublicKeyAlgorithm, "SignatureTarget public-key-algorithm mismatch");
            Assert.AreEqual(8, target.HashAlgorithm, "SignatureTarget hash-algorithm mismatch");
            Assert.AreEqual(0, target.GetHashData().Length, "SignatureTarget hash-data should be empty");

            RevocationKey revocationKey = new RevocationKey(false, false,
                new byte[]{ (byte)RevocationKeyTag.ClassDefault, (byte)PublicKeyAlgorithmTag.RsaGeneral });
            Assert.AreEqual(RevocationKeyTag.ClassDefault, revocationKey.SignatureClass,
                "RevocationKey signature-class mismatch");
            Assert.AreEqual(PublicKeyAlgorithmTag.RsaGeneral, revocationKey.Algorithm,
                "RevocationKey algorithm mismatch");
            Assert.AreEqual(0, revocationKey.GetFingerprint().Length, "RevocationKey fingerprint should be empty");

            RevocationReason revocationReason = new RevocationReason(false, false,
                new byte[]{ (byte)RevocationReasonTag.KeyRetired });
            Assert.AreEqual(RevocationReasonTag.KeyRetired, revocationReason.GetRevocationReason(),
                "RevocationReason code mismatch");
            Assert.AreEqual("", revocationReason.GetRevocationDescription(),
                "RevocationReason description should be empty");

            // a NotationData body exactly 8 + nameLength + valueLength long is accepted and its
            // name/value accessors read back correctly. Here name = "x" (1 octet), value empty.
            byte[] notation = NotationBody(1, 0, 1);
            notation[8] = (byte)'x';
            NotationData notationData = new NotationData(false, false, notation);
            Assert.AreEqual("x", notationData.GetNotationName(), "NotationData name mismatch");
            Assert.AreEqual(0, notationData.GetNotationValueBytes().Length, "NotationData value should be empty");
        }

        private static void CheckConstructionRejected(String name, byte[] body)
        {
            try
            {
                Construct(name, body);
                Assert.Fail($"{name} accepted a truncated {body.Length}-octet body");
            }
            catch (ArgumentException)
            {
                // expected - the parse constructor rejects a body too short for its accessors
            }
        }

        private static void CheckWireDecodeRejected(SignatureSubpacketTag type, int subpacketLength)
        {
            // OpenPGP signature subpacket framing: a one-octet length field (< 192) covering the
            // type octet plus body, the type octet, then (subpacketLength - 1) body octets (left
            // zero here so the body is too short for the subpacket's accessors).
            byte[] encoded = new byte[1 + subpacketLength];
            encoded[0] = (byte)subpacketLength;
            encoded[1] = (byte)type;

            SignatureSubpacketsParser sIn = new SignatureSubpacketsParser(new MemoryStream(encoded, false));
            try
            {
                sIn.ReadPacket();
                Assert.Fail("Wire decode accepted a truncated subpacket of type " + type);
            }
            catch (MalformedPacketException)
            {
                // expected - the constructor's ArgumentException surfaced at decode time
            }
        }

        private static void CheckWireDecodeRejected(SignatureSubpacketTag type, byte[] body)
        {
            // as above, but with a caller-supplied body (for subpackets like NotationData whose
            // truncation depends on internal length fields rather than a fixed minimum length).
            byte[] encoded = new byte[1 + 1 + body.Length];
            encoded[0] = (byte)(1 + body.Length);
            encoded[1] = (byte)type;
            Array.Copy(body, 0, encoded, 2, body.Length);

            SignatureSubpacketsParser sIn = new SignatureSubpacketsParser(new MemoryStream(encoded, false));
            try
            {
                sIn.ReadPacket();
                Assert.Fail("Wire decode accepted a truncated subpacket of type " + type);
            }
            catch (MalformedPacketException)
            {
                // expected - the constructor's ArgumentException surfaced at decode time
            }
        }

        private static SignatureSubpacket Construct(string name, byte[] body)
        {
            switch (name)
            {
            case "Features":
                return new Features(false, false, body);

            case "TrustSignature":
                return new TrustSignature(false, false, body);

            case "SignatureTarget":
                return new SignatureTarget(false, false, body);

            case "RevocationKey":
                return new RevocationKey(false, false, body);

            case "RevocationReason":
                return new RevocationReason(false, false, body);

            case "NotationData":
                return new NotationData(false, false, body);

            default:
                throw new InvalidOperationException("unknown subpacket: " + name);
            }
        }

        /// <summary>
        /// Build a raw NotationData body: the 8-octet header (4 flag octets, a 2-octet name length and a 2-octet value
        /// length) followed by <paramref name="payloadLength"/> body octets.
        /// </summary>
        /// <remarks>
        /// Passing a payloadLength smaller than <c><paramref name="nameLength"/> + <paramref name="valueLength"/></c>
        /// yields a truncated packet.
        /// </remarks>
        private static byte[] NotationBody(int nameLength, int valueLength, int payloadLength)
        {
            byte[] body = new byte[8 + payloadLength];
            body[4] = (byte)(nameLength >> 8);
            body[5] = (byte)nameLength;
            body[6] = (byte)(valueLength >> 8);
            body[7] = (byte)valueLength;
            return body;
        }
    }
}
