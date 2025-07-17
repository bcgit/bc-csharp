using System;
using System.IO;

using Org.BouncyCastle.Asn1.Cryptlib;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>A public key encrypted data object.</remarks>
    public class PgpPublicKeyEncryptedData
        : PgpEncryptedData
    {
        private readonly PublicKeyEncSessionPacket m_keyData;

        internal PgpPublicKeyEncryptedData(PublicKeyEncSessionPacket keyData, InputStreamPacket encData)
            : base(encData)
        {
            m_keyData = keyData;
        }

        private static IBufferedCipher GetKeyCipher(PublicKeyAlgorithmTag algorithm)
        {
            try
            {
                switch (algorithm)
                {
                case PublicKeyAlgorithmTag.RsaEncrypt:
                case PublicKeyAlgorithmTag.RsaGeneral:
                    return CipherUtilities.GetCipher("RSA//PKCS1Padding");
                case PublicKeyAlgorithmTag.ElGamalEncrypt:
                case PublicKeyAlgorithmTag.ElGamalGeneral:
                    return CipherUtilities.GetCipher("ElGamal/ECB/PKCS1Padding");
                default:
                    throw new PgpException("unknown asymmetric algorithm: " + algorithm);
                }
            }
            catch (PgpException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception creating cipher", e);
            }
        }

        /// <summary>The Key ID for the key used to encrypt the data.</summary>
        /// <remarks>
        /// A Key ID is an 8-octet scalar. We convert it (big-endian) to an Int64 (UInt64 is not CLS compliant).
        /// </remarks>
        public long KeyId => m_keyData.KeyId;

        /// <summary>
        /// Return the algorithm code for the symmetric algorithm used to encrypt the data.
        /// </summary>
        public SymmetricKeyAlgorithmTag GetSymmetricAlgorithm(PgpPrivateKey privKey)
        {
            byte[] sessionData = RecoverSessionData(privKey);

            return (SymmetricKeyAlgorithmTag)sessionData[0];
        }

        /// <summary>Return the decrypted data stream for the packet.</summary>
        public Stream GetDataStream(PgpPrivateKey privKey)
        {
            byte[] sessionData = RecoverSessionData(privKey);

            if (!ConfirmCheckSum(sessionData))
                throw new PgpKeyValidationException("key checksum failed");

            SymmetricKeyAlgorithmTag symmAlg = (SymmetricKeyAlgorithmTag)sessionData[0];
            if (symmAlg == SymmetricKeyAlgorithmTag.Null)
                return GetInputStream();

            string cipherName = PgpUtilities.GetSymmetricCipherName(symmAlg);

            IBufferedCipher cipher;
            try
            {
                cipher = CreateBufferedCipher(cipherName);
            }
            catch (PgpException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new PgpException("exception creating cipher", e);
            }

            try
            {
                var key = ParameterUtilities.CreateKeyParameter(cipherName, sessionData, 1, sessionData.Length - 3);

                cipher.Init(forEncryption: false, new ParametersWithIV(key, iv: new byte[cipher.GetBlockSize()]));

                var decStream = InitDecStream(new CipherStream(GetInputStream(), cipher, null));

                byte[] prefix = StreamUtilities.RequireBytes(decStream, cipher.GetBlockSize() + 2);

                /*
                 * The oracle attack on the "quick check" bytes is deemed a security risk for typical public key
                 * encryption usages, therefore we do not perform the check.
                 */
                //QuickCheck(prefix);

                return decStream;
            }
            catch (PgpException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception starting decryption", e);
            }
        }

        private byte[] RecoverSessionData(PgpPrivateKey privKey)
        {
            byte[][] secKeyData = m_keyData.GetEncSessionKey();

            if (m_keyData.Algorithm != PublicKeyAlgorithmTag.ECDH)
            {
                IBufferedCipher cipher = GetKeyCipher(m_keyData.Algorithm);

                try
                {
                    cipher.Init(forEncryption: false, privKey.Key);
                }
                catch (InvalidKeyException e)
                {
                    throw new PgpException("error setting asymmetric cipher", e);
                }

                if (m_keyData.Algorithm == PublicKeyAlgorithmTag.RsaEncrypt ||
                    m_keyData.Algorithm == PublicKeyAlgorithmTag.RsaGeneral)
                {
                    byte[] bi = secKeyData[0];

                    cipher.ProcessBytes(bi, 2, bi.Length - 2);
                }
                else
                {
                    ElGamalPrivateKeyParameters k = (ElGamalPrivateKeyParameters)privKey.Key;
                    int size = (k.Parameters.P.BitLength + 7) / 8;

                    ProcessEncodedMpi(cipher, size, secKeyData[0]);
                    ProcessEncodedMpi(cipher, size, secKeyData[1]);
                }

                try
                {
                    return cipher.DoFinal();
                }
                catch (Exception e)
                {
                    throw new PgpException("exception decrypting secret key", e);
                }
            }

            ECDHPublicBcpgKey ecPubKey = (ECDHPublicBcpgKey)privKey.PublicKeyPacket.Key;
            byte[] enc = secKeyData[0];

            int pLen = (Pack.BE_To_UInt16(enc, 0) + 7) / 8;
            if ((2 + pLen + 1) > enc.Length)
                throw new PgpException("encoded length out of range");

            byte[] pEnc = new byte[pLen];
            Array.Copy(enc, 2, pEnc, 0, pLen);

            int keyLen = enc[pLen + 2];
            if ((2 + pLen + 1 + keyLen) > enc.Length)
                throw new PgpException("encoded length out of range");

            byte[] keyEnc = new byte[keyLen];
            Array.Copy(enc, 2 + pLen + 1, keyEnc, 0, keyEnc.Length);

            var curveOid = ecPubKey.CurveOid;
            byte[] secret;

            if (EdECObjectIdentifiers.id_X25519.Equals(curveOid) ||
                CryptlibObjectIdentifiers.curvey25519.Equals(curveOid))
            {
                // skip the 0x40 header byte.
                if (pEnc.Length != (1 + X25519PublicKeyParameters.KeySize) || 0x40 != pEnc[0])
                    throw new ArgumentException("Invalid X25519 public key");

                X25519PublicKeyParameters ephPub = new X25519PublicKeyParameters(pEnc, 1);

                X25519Agreement agreement = new X25519Agreement();
                agreement.Init(privKey.Key);

                secret = new byte[agreement.AgreementSize];
                agreement.CalculateAgreement(ephPub, secret, 0);
            }
            else if (EdECObjectIdentifiers.id_X448.Equals(curveOid))
            {
                // skip the 0x40 header byte.
                if (pEnc.Length != (1 + X448PublicKeyParameters.KeySize) || 0x40 != pEnc[0])
                    throw new ArgumentException("Invalid X448 public key");

                X448PublicKeyParameters ephPub = new X448PublicKeyParameters(pEnc, 1);

                X448Agreement agreement = new X448Agreement();
                agreement.Init(privKey.Key);

                secret = new byte[agreement.AgreementSize];
                agreement.CalculateAgreement(ephPub, secret, 0);
            }
            else
            {
                ECDomainParameters ecParameters = ((ECPrivateKeyParameters)privKey.Key).Parameters;

                ECPublicKeyParameters ephPub = new ECPublicKeyParameters(ecParameters.Curve.DecodePoint(pEnc),
                    ecParameters);

                ECDHBasicAgreement agreement = new ECDHBasicAgreement();
                agreement.Init(privKey.Key);
                BigInteger S = agreement.CalculateAgreement(ephPub);
                secret = BigIntegers.AsUnsignedByteArray(agreement.GetFieldSize(), S);
            }

            KeyParameter key = new KeyParameter(Rfc6637Utilities.CreateKey(privKey.PublicKeyPacket, secret));

            IWrapper wrapper = PgpUtilities.CreateWrapper(ecPubKey.SymmetricKeyAlgorithm);
            wrapper.Init(forWrapping: false, key);

            return PgpPad.UnpadSessionData(wrapper.Unwrap(keyEnc, 0, keyEnc.Length));
        }

        private static bool ConfirmCheckSum(byte[] sessionInfo)
        {
            int check = 0;

            for (int i = 1; i < sessionInfo.Length - 2; ++i)
            {
                check += sessionInfo[i];
            }

            return Pack.BE_To_UInt16(sessionInfo, sessionInfo.Length - 2) == (ushort)check;
        }

        private static void ProcessEncodedMpi(IBufferedCipher cipher, int size, byte[] mpiEnc)
        {
            if (mpiEnc.Length - 2 > size)  // leading Zero? Shouldn't happen but...
            {
                cipher.ProcessBytes(mpiEnc, 3, mpiEnc.Length - 3);
            }
            else
            {
                byte[] tmp = new byte[size];
                Array.Copy(mpiEnc, 2, tmp, tmp.Length - (mpiEnc.Length - 2), mpiEnc.Length - 2);
                cipher.ProcessBytes(tmp, 0, tmp.Length);
            }
        }
    }
}
