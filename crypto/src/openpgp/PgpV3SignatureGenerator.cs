using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>Generator for old style PGP V3 Signatures.</remarks>
    public class PgpV3SignatureGenerator
    {
        private readonly PublicKeyAlgorithmTag m_keyAlgorithm;
        private readonly HashAlgorithmTag m_hashAlgorithm;

        private PgpPrivateKey privKey;
        private ISigner sig;
        private IDigest dig;
        private int signatureType;
        private byte lastb;

        /// <summary>Create a generator for the passed in keyAlgorithm and hashAlgorithm codes.</summary>
        public PgpV3SignatureGenerator(PublicKeyAlgorithmTag keyAlgorithm, HashAlgorithmTag hashAlgorithm)
        {
            if (keyAlgorithm == PublicKeyAlgorithmTag.EdDsa_Legacy)
                throw new ArgumentException("Invalid algorithm for V3 signature", nameof(keyAlgorithm));

            m_keyAlgorithm = keyAlgorithm;
            m_hashAlgorithm = hashAlgorithm;

            dig = PgpUtilities.CreateDigest(hashAlgorithm);
        }

        /// <summary>Initialise the generator for signing.</summary>
        public void InitSign(int sigType, PgpPrivateKey privKey) => InitSign(sigType, privKey, random: null);

        /// <summary>Initialise the generator for signing.</summary>
        public void InitSign(int sigType, PgpPrivateKey privKey, SecureRandom random)
        {
            this.privKey = privKey;
            this.signatureType = sigType;

            AsymmetricKeyParameter key = privKey.Key;

            this.sig = PgpUtilities.CreateSigner(m_keyAlgorithm, m_hashAlgorithm, key);

            try
            {
                sig.Init(forSigning: true, ParameterUtilities.WithRandom(key, random));
            }
            catch (InvalidKeyException e)
            {
                throw new PgpException("invalid key.", e);
            }

            dig.Reset();
            lastb = 0;
        }

        public void Update(byte b)
        {
            if (signatureType == PgpSignature.CanonicalTextDocument)
            {
                DoCanonicalUpdateByte(b);
            }
            else
            {
                DoUpdateByte(b);
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
                DoUpdateByte(b);
            }

            lastb = b;
        }

        private void DoUpdateCRLF()
        {
            DoUpdateByte((byte)'\r');
            DoUpdateByte((byte)'\n');
        }

        private void DoUpdateByte(
            byte b)
        {
            sig.Update(b);
            dig.Update(b);
        }

        public void Update(params byte[] b) => Update(b, 0, b.Length);

        public void Update(byte[] b, int off, int len)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Update(b.AsSpan(off, len));
#else
            if (signatureType == PgpSignature.CanonicalTextDocument)
            {
                for (int i = 0; i < len; ++i)
                {
                    DoCanonicalUpdateByte(b[off + i]);
                }
            }
            else
            {
                sig.BlockUpdate(b, off, len);
                dig.BlockUpdate(b, off, len);
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void Update(ReadOnlySpan<byte> input)
        {
            if (signatureType == PgpSignature.CanonicalTextDocument)
            {
                for (int i = 0; i < input.Length; ++i)
                {
                    DoCanonicalUpdateByte(input[i]);
                }
            }
            else
            {
                sig.BlockUpdate(input);
                dig.BlockUpdate(input);
            }
        }
#endif

        /// <summary>Return the one pass header associated with the current signature.</summary>
        public PgpOnePassSignature GenerateOnePassVersion(bool isNested)
        {
            return new PgpOnePassSignature(
                new OnePassSignaturePacket(signatureType, m_hashAlgorithm, m_keyAlgorithm, privKey.KeyId, isNested));
        }

        /// <summary>Return a V3 signature object containing the current signature state.</summary>
        public PgpSignature Generate()
        {
            long creationTime = DateTimeUtilities.CurrentUnixMs() / 1000L;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> hData = stackalloc byte[5];
            hData[0] = (byte)signatureType;
            Pack.UInt32_To_BE((uint)creationTime, hData, 1);

            sig.BlockUpdate(hData);
            dig.BlockUpdate(hData);
#else
            byte[] hData = new byte[5];
            hData[0] = (byte)signatureType;
            Pack.UInt32_To_BE((uint)creationTime, hData, 1);

            sig.BlockUpdate(hData, 0, hData.Length);
            dig.BlockUpdate(hData, 0, hData.Length);
#endif

            byte[] sigBytes = sig.GenerateSignature();
            byte[] digest = DigestUtilities.DoFinal(dig);
            byte[] fingerPrint = new byte[]{ digest[0], digest[1] };

            // an RSA signature
            bool isRsa =
                m_keyAlgorithm == PublicKeyAlgorithmTag.RsaSign ||
                m_keyAlgorithm == PublicKeyAlgorithmTag.RsaGeneral;

            MPInteger[] sigValues = isRsa
                ? PgpUtilities.RsaSigToMpi(sigBytes)
                : PgpUtilities.DsaSigToMpi(sigBytes);

            var sigPacket = new SignaturePacket(3, signatureType, privKey.KeyId, m_keyAlgorithm, m_hashAlgorithm,
                creationTime * 1000L, fingerPrint, sigValues);

            return new PgpSignature(sigPacket);
        }
    }
}
