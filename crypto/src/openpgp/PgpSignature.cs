using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>A PGP signature object.</remarks>
    public class PgpSignature
    {
        private static SignaturePacket Cast(Packet packet)
        {
            if (packet is SignaturePacket signaturePacket)
                return signaturePacket;

            throw new IOException("unexpected packet in stream: " + packet);
        }

        /// <summary>The <c>BinaryDocument</c> constant, with the value <c>0x00</c>.</summary>
        public const int BinaryDocument = 0x00;
        /// <summary>The <c>CanonicalTextDocument</c> constant, with the value <c>0x01</c>.</summary>
        public const int CanonicalTextDocument = 0x01;
        /// <summary>The <c>StandAlone</c> constant, with the value <c>0x02</c>.</summary>
        public const int StandAlone = 0x02;

        /// <summary>The <c>DefaultCertification</c> constant, with the value <c>0x10</c>.</summary>
        public const int DefaultCertification = 0x10;
        /// <summary>The <c>NoCertification</c> constant, with the value <c>0x11</c>.</summary>
        public const int NoCertification = 0x11;
        /// <summary>The <c>CasualCertification</c> constant, with the value <c>0x12</c>.</summary>
        public const int CasualCertification = 0x12;
        /// <summary>The <c>PositiveCertification</c> constant, with the value <c>0x13</c>.</summary>
        public const int PositiveCertification = 0x13;

        /// <summary>The <c>SubkeyBinding</c> constant, with the value <c>0x18</c>.</summary>
        public const int SubkeyBinding = 0x18;
        /// <summary>The <c>PrimaryKeyBinding</c> constant, with the value <c>0x19</c>.</summary>
        public const int PrimaryKeyBinding = 0x19;
        /// <summary>The <c>DirectKey</c> constant, with the value <c>0x1f</c>.</summary>
        public const int DirectKey = 0x1f;
        /// <summary>The <c>KeyRevocation</c> constant, with the value <c>0x20</c>.</summary>
        public const int KeyRevocation = 0x20;
        /// <summary>The <c>SubkeyRevocation</c> constant, with the value <c>0x28</c>.</summary>
        public const int SubkeyRevocation = 0x28;
        /// <summary>The <c>CertificationRevocation</c> constant, with the value <c>0x30</c>.</summary>
        public const int CertificationRevocation = 0x30;
        /// <summary>The <c>Timestamp</c> constant, with the value <c>0x40</c>.</summary>
        public const int Timestamp = 0x40;
        /// <summary>The <c>ThirdPartyConfirmation</c> constant, with the value <c>0x50</c>.</summary>
        public const int ThirdPartyConfirmation = 0x50;

        private readonly SignaturePacket sigPck;
        private readonly int signatureType;
        private readonly TrustPacket trustPck;

        private ISigner sig;
        private byte lastb; // Initial value anything but '\r'

        internal PgpSignature(
            BcpgInputStream bcpgInput)
            : this(Cast(bcpgInput.ReadPacket()))
        {
        }

        internal PgpSignature(SignaturePacket sigPacket)
            : this(sigPacket, null)
        {
        }

        internal PgpSignature(SignaturePacket sigPacket, TrustPacket trustPacket)
        {
            this.sigPck = sigPacket ?? throw new ArgumentNullException(nameof(sigPacket));
            this.signatureType = sigPck.SignatureType;
            this.trustPck = trustPacket;
        }

        /// <summary>The OpenPGP version number for this signature.</summary>
        public int Version
        {
            get { return sigPck.Version; }
        }

        /// <summary>The key algorithm associated with this signature.</summary>
        public PublicKeyAlgorithmTag KeyAlgorithm
        {
            get { return sigPck.KeyAlgorithm; }
        }

        /// <summary>The hash algorithm associated with this signature.</summary>
        public HashAlgorithmTag HashAlgorithm
        {
            get { return sigPck.HashAlgorithm; }
        }

        /// <summary>Return the digest prefix of the signature.</summary>
        public byte[] GetDigestPrefix()
        {
            return sigPck.GetFingerprint();
        }

        /// <summary>Return true if this signature represents a certification.</summary>
        public bool IsCertification()
        {
            return IsCertification(SignatureType);
        }

        public void InitVerify(PgpPublicKey pubKey)
        {
            lastb = 0;
            AsymmetricKeyParameter key = pubKey.GetKey();

            if (sig == null)
            {
                this.sig = PgpUtilities.CreateSigner(sigPck.KeyAlgorithm, sigPck.HashAlgorithm, key);
            }

            try
            {
                sig.Init(false, key);
            }
            catch (InvalidKeyException e)
            {
                throw new PgpException("invalid key.", e);
            }
        }

        public void Update(byte b)
        {
            if (signatureType == CanonicalTextDocument)
            {
                DoCanonicalUpdateByte(b);
            }
            else
            {
                sig.Update(b);
            }
        }

        private void DoCanonicalUpdateByte(byte b)
        {
            if (b == '\r')
            {
                DoUpdateCRLF();
            }
            else if (b == '\n')
            {
                if (lastb != '\r')
                {
                    DoUpdateCRLF();
                }
            }
            else
            {
                sig.Update(b);
            }

            lastb = b;
        }

        private void DoUpdateCRLF()
        {
            sig.Update((byte)'\r');
            sig.Update((byte)'\n');
        }

        public void Update(params byte[] bytes)
        {
            Update(bytes, 0, bytes.Length);
        }

        public void Update(byte[] bytes, int off, int length)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Update(bytes.AsSpan(off, length));
#else
            if (signatureType == CanonicalTextDocument)
            {
                int finish = off + length;

                for (int i = off; i != finish; i++)
                {
                    DoCanonicalUpdateByte(bytes[i]);
                }
            }
            else
            {
                sig.BlockUpdate(bytes, off, length);
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void Update(ReadOnlySpan<byte> input)
        {
            if (signatureType == CanonicalTextDocument)
            {
                for (int i = 0; i < input.Length; ++i)
                {
                    DoCanonicalUpdateByte(input[i]);
                }
            }
            else
            {
                sig.BlockUpdate(input);
            }
        }
#endif

        public bool Verify()
        {
            byte[] trailer = GetSignatureTrailer();

            sig.BlockUpdate(trailer, 0, trailer.Length);

            return sig.VerifySignature(GetSignature());
        }

        private void UpdateWithIdData(int header, byte[] idBytes)
        {
            this.Update(
                (byte) header,
                (byte)(idBytes.Length >> 24),
                (byte)(idBytes.Length >> 16),
                (byte)(idBytes.Length >> 8),
                (byte)(idBytes.Length));
            this.Update(idBytes);
        }

        private void UpdateWithPublicKey(PgpPublicKey key)
        {
            byte[] keyBytes = GetEncodedPublicKey(key);

            this.Update(
                (byte) 0x99,
                (byte)(keyBytes.Length >> 8),
                (byte)(keyBytes.Length));
            this.Update(keyBytes);
        }

        /// <summary>
        /// Verify the signature as certifying the passed in public key as associated
        /// with the passed in user attributes.
        /// </summary>
        /// <param name="userAttributes">User attributes the key was stored under.</param>
        /// <param name="key">The key to be verified.</param>
        /// <returns>True, if the signature matches, false otherwise.</returns>
        public bool VerifyCertification(PgpUserAttributeSubpacketVector userAttributes, PgpPublicKey key)
        {
            UpdateWithPublicKey(key);

            //
            // hash in the userAttributes
            //
            try
            {
                var bOut = new MemoryStream();
                foreach (UserAttributeSubpacket packet in userAttributes.ToSubpacketArray())
                {
                    packet.Encode(bOut);
                }
                UpdateWithIdData(0xd1, bOut.ToArray());
            }
            catch (IOException e)
            {
                throw new PgpException("cannot encode subpacket array", e);
            }

            return Verify();
        }

        /// <summary>
        /// Verify the signature as certifying the passed in public key as associated
        /// with the passed in ID.
        /// </summary>
        /// <param name="id">ID the key was stored under.</param>
        /// <param name="key">The key to be verified.</param>
        /// <returns>True, if the signature matches, false otherwise.</returns>
        public bool VerifyCertification(string id, PgpPublicKey key)
        {
            UpdateWithPublicKey(key);

            //
            // hash in the id
            //
            UpdateWithIdData(0xb4, Strings.ToUtf8ByteArray(id));

            return Verify();
        }

        /// <summary>Verify a certification for the passed in key against the passed in master key.</summary>
        /// <param name="masterKey">The key we are verifying against.</param>
        /// <param name="pubKey">The key we are verifying.</param>
        /// <returns>True, if the certification is valid, false otherwise.</returns>
        public bool VerifyCertification(
            PgpPublicKey masterKey,
            PgpPublicKey pubKey)
        {
            UpdateWithPublicKey(masterKey);
            UpdateWithPublicKey(pubKey);

            return Verify();
        }

        /// <summary>Verify a key certification, such as revocation, for the passed in key.</summary>
        /// <param name="pubKey">The key we are checking.</param>
        /// <returns>True, if the certification is valid, false otherwise.</returns>
        public bool VerifyCertification(
            PgpPublicKey pubKey)
        {
            if (SignatureType != KeyRevocation
                && SignatureType != SubkeyRevocation)
            {
                throw new InvalidOperationException("signature is not a key signature");
            }

            UpdateWithPublicKey(pubKey);

            return Verify();
        }

        /// <summary>Gets the signature type.</summary>
        public int SignatureType
        {
            get { return sigPck.SignatureType; }
        }

        /// <summary>The Key ID of the key that created the signature.</summary>
        /// <remarks>
        /// A Key ID is an 8-octet scalar. We convert it (big-endian) to an Int64 (UInt64 is not CLS compliant).
        /// </remarks>
        public long KeyId => sigPck.KeyId;

        /// <summary>The creation time of this signature.</summary>
        public DateTime CreationTime
        {
            get { return DateTimeUtilities.UnixMsToDateTime(sigPck.CreationTime); }
        }

        /// <summary>Return the signature trailer.</summary>
        public byte[] GetSignatureTrailer()
        {
            return sigPck.GetSignatureTrailer();
        }

        /// <summary>
        /// Return true if the signature has either hashed or unhashed subpackets.
        /// </summary>
        public bool HasSubpackets
        {
            get
            {
                return sigPck.GetHashedSubPackets() != null
                    || sigPck.GetUnhashedSubPackets() != null;
            }
        }

        /// <summary>Return the hashed sub packets.</summary>
        public PgpSignatureSubpacketVector GetHashedSubPackets()
        {
            return CreateSubpacketVector(sigPck.GetHashedSubPackets());
        }

        /// <summary>Return the unhashed sub packets.</summary>
        public PgpSignatureSubpacketVector GetUnhashedSubPackets()
        {
            return CreateSubpacketVector(sigPck.GetUnhashedSubPackets());
        }

        private static PgpSignatureSubpacketVector CreateSubpacketVector(SignatureSubpacket[] pcks)
        {
            return pcks == null ? null : new PgpSignatureSubpacketVector(pcks);
        }

        /// <summary>Return the salt of a v6 signature.</summary>
        internal byte[] GetSalt() => sigPck.GetSalt();

        /// <summary>Return the signature.</summary>
        public byte[] GetSignature()
        {
            MPInteger[] sigValues = sigPck.GetSignature();
            byte[] signature;

            if (sigValues != null)
            {
                if (sigValues.Length == 1)    // an RSA signature
                {
                    signature = sigValues[0].Value.ToByteArrayUnsigned();
                }
                else if (KeyAlgorithm == PublicKeyAlgorithmTag.EdDsa_Legacy)
                {
                    if (sigValues.Length != 2)
                        throw new InvalidOperationException();

                    BigInteger v0 = sigValues[0].Value;
                    BigInteger v1 = sigValues[1].Value;

                    if (v0.BitLength == 918 &&
                        v1.Equals(BigInteger.Zero) &&
                        v0.ShiftRight(912).Equals(BigInteger.ValueOf(0x40)))
                    {
                        signature = new byte[Ed448.SignatureSize];
                        BigIntegers.AsUnsignedByteArray(v0.ClearBit(918), signature, 0, signature.Length);
                    }
                    else if (v0.BitLength <= 256 && v1.BitLength <= 256)
                    {
                        signature = new byte[Ed25519.SignatureSize];
                        BigIntegers.AsUnsignedByteArray(sigValues[0].Value, signature, 0, 32);
                        BigIntegers.AsUnsignedByteArray(sigValues[1].Value, signature, 32, 32);
                    }
                    else
                    {
                        throw new PgpException("Malformed EdDsa legacy signature encoding (too long).");
                    }
                }
                else
                {
                    if (sigValues.Length != 2)
                        throw new InvalidOperationException();

                    try
                    {
                        signature = new DerSequence(
                            new DerInteger(sigValues[0].Value),
                            new DerInteger(sigValues[1].Value)).GetEncoded();
                    }
                    catch (IOException e)
                    {
                        throw new PgpException("exception encoding DSA sig.", e);
                    }
                }
            }
            else
            {
                signature = sigPck.GetSignatureBytes();
            }

            return signature;
        }

        /// <summary>Return the encoded.</summary>
        // TODO Handle the encoding stuff by subclassing BcpgObject?
        public byte[] GetEncoded()
        {
            var bOut = new MemoryStream();

            Encode(bOut);

            return bOut.ToArray();
        }

        /// <summary>Return the encoded.</summary>
        /// <param name="outStream">The output stream.</param>
        public void Encode(Stream outStream)
        {
            Encode(outStream, false);
        }

        /**
         * Encode the signature to outStream, with trust packets stripped out if forTransfer is true.
         *
         * @param outStream   stream to write the key encoding to.
         * @param forTransfer if the purpose of encoding is to send key to other users.
         * @throws IOException in case of encoding error.
         */
        public void Encode(Stream outStream, bool forTransfer)
        {
            // Exportable signatures MUST NOT be exported if forTransfer==true
            if (forTransfer && (IsNotExportable(GetHashedSubPackets()) || IsNotExportable(GetUnhashedSubPackets())))
                return;

            var bcpgOut = BcpgOutputStream.Wrap(outStream);

            sigPck.Encode(bcpgOut);

            if (!forTransfer)
            {
                trustPck?.Encode(bcpgOut);
            }
        }

        private static byte[] GetEncodedPublicKey(PgpPublicKey pubKey)
        {
            try
            {
                return pubKey.publicPk.GetEncodedContents();
            }
            catch (IOException e)
            {
                throw new PgpException("exception preparing key.", e);
            }
        }

        /// <summary>
        /// Return true if the passed in signature type represents a certification, false if the signature type is not.
        /// </summary>
        /// <param name="signatureType"></param>
        /// <returns>true if signatureType is a certification, false otherwise.</returns>
        public static bool IsCertification(int signatureType)
        {
            switch (signatureType)
            {
            case DefaultCertification:
            case NoCertification:
            case CasualCertification:
            case PositiveCertification:
                return true;
            default:
                return false;
            }
        }

        private static bool IsNotExportable(PgpSignatureSubpacketVector subPackets) =>
            subPackets != null && !subPackets.IsExportable();

        public static bool IsSignatureEncodingEqual(PgpSignature sig1, PgpSignature sig2)
        {
            return Arrays.AreEqual(sig1.sigPck.GetSignatureBytes(), sig2.sigPck.GetSignatureBytes());
        }

        public static PgpSignature Join(PgpSignature sig1, PgpSignature sig2)
        {
            if (!IsSignatureEncodingEqual(sig1, sig2))
                throw new ArgumentException("These are different signatures.");

            // merge unhashed subpackets
            SignatureSubpacket[] sig1Unhashed = sig1.GetUnhashedSubPackets().ToSubpacketArray();
            SignatureSubpacket[] sig2Unhashed = sig2.GetUnhashedSubPackets().ToSubpacketArray();

            var merged = new List<SignatureSubpacket>(sig1Unhashed);

            foreach (var subpacket in sig2Unhashed)
            {
                if (!merged.Contains(subpacket))
                {
                    merged.Add(subpacket);
                }
            }

            SignatureSubpacket[] unhashed = merged.ToArray();
            return new PgpSignature(
                new SignaturePacket(
                    sig1.SignatureType,
                    sig1.KeyId,
                    sig1.KeyAlgorithm,
                    sig1.HashAlgorithm,
                    sig1.GetHashedSubPackets().ToSubpacketArray(),
                    unhashed,
                    sig1.GetDigestPrefix(),
                    sig1.sigPck.GetSignature()
                )
            );
        }
    }
}
