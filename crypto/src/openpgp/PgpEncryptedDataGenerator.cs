using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;

using Org.BouncyCastle.Asn1.Cryptlib;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>Generator for encrypted objects.</summary>
    public class PgpEncryptedDataGenerator
        : IStreamGenerator
    {
        private BcpgOutputStream pOut;
        private CipherStream cOut;
        private IBufferedCipher c;
        private bool withIntegrityPacket;
        private bool oldFormat;
        private DigestStream digestOut;

        private abstract class EncMethod
            : ContainedPacket
        {
            protected byte[] sessionInfo;
            protected SymmetricKeyAlgorithmTag encAlgorithm;
            protected KeyParameter key;

            public abstract void AddSessionInfo(byte[] si, SecureRandom random);
        }

        private class PbeMethod
            : EncMethod
        {
            private readonly S2k m_s2k;

            internal PbeMethod(SymmetricKeyAlgorithmTag encAlgorithm, S2k s2k, KeyParameter key)
            {
                this.encAlgorithm = encAlgorithm;
                m_s2k = s2k;
                this.key = key;
            }

            public KeyParameter GetKey() => key;

            public override void AddSessionInfo(byte[] si, SecureRandom random)
            {
                string cName = PgpUtilities.GetSymmetricCipherName(encAlgorithm);
                IBufferedCipher c = CipherUtilities.GetCipher(cName + "/CFB/NoPadding");

                byte[] iv = new byte[c.GetBlockSize()];
                c.Init(true, new ParametersWithRandom(new ParametersWithIV(key, iv), random));

                this.sessionInfo = c.DoFinal(si, 0, si.Length - 2);
            }

            public override void Encode(BcpgOutputStream pOut) =>
                new SymmetricKeyEncSessionPacket(encAlgorithm, m_s2k, sessionInfo).Encode(pOut);
        }

        private class PubMethod
            : EncMethod
        {
            internal PgpPublicKey pubKey;
            internal bool sessionKeyObfuscation;
            internal byte[][] data;

            internal PubMethod(PgpPublicKey pubKey, bool sessionKeyObfuscation)
            {
                this.pubKey = pubKey;
                this.sessionKeyObfuscation = sessionKeyObfuscation;
            }

            public override void AddSessionInfo(
                byte[] sessionInfo,
                SecureRandom random)
            {
                byte[] encryptedSessionInfo = EncryptSessionInfo(sessionInfo, random);

                this.data = ProcessSessionInfo(encryptedSessionInfo);
            }

            private byte[] EncryptSessionInfo(byte[] sessionInfo, SecureRandom random)
            {
                var cryptoPublicKey = pubKey.GetKey();

                if (pubKey.Algorithm != PublicKeyAlgorithmTag.ECDH)
                {
                    IBufferedCipher c;
                    switch (pubKey.Algorithm)
                    {
                    case PublicKeyAlgorithmTag.RsaEncrypt:
                    case PublicKeyAlgorithmTag.RsaGeneral:
                        c = CipherUtilities.GetCipher("RSA//PKCS1Padding");
                        break;
                    case PublicKeyAlgorithmTag.ElGamalEncrypt:
                    case PublicKeyAlgorithmTag.ElGamalGeneral:
                        c = CipherUtilities.GetCipher("ElGamal/ECB/PKCS1Padding");
                        break;
                    case PublicKeyAlgorithmTag.Dsa:
                        throw new PgpException("Can't use DSA for encryption.");
                    case PublicKeyAlgorithmTag.ECDsa:
                        throw new PgpException("Can't use ECDSA for encryption.");
                    case PublicKeyAlgorithmTag.EdDsa_Legacy:
                        throw new PgpException("Can't use EdDSA for encryption.");
                    default:
                        throw new PgpException("unknown asymmetric algorithm: " + pubKey.Algorithm);
                    }

                    c.Init(true, new ParametersWithRandom(cryptoPublicKey, random));
                    return c.DoFinal(sessionInfo);
                }

                ECDHPublicBcpgKey ecPubKey = (ECDHPublicBcpgKey)pubKey.PublicKeyPacket.Key;
                var curveOid = ecPubKey.CurveOid;

                if (EdECObjectIdentifiers.id_X25519.Equals(curveOid) ||
                    CryptlibObjectIdentifiers.curvey25519.Equals(curveOid))
                {
                    X25519KeyPairGenerator gen = new X25519KeyPairGenerator();
                    gen.Init(new X25519KeyGenerationParameters(random));

                    AsymmetricCipherKeyPair ephKp = gen.GenerateKeyPair();

                    X25519Agreement agreement = new X25519Agreement();
                    agreement.Init(ephKp.Private);

                    byte[] secret = new byte[agreement.AgreementSize];
                    agreement.CalculateAgreement(cryptoPublicKey, secret, 0);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    Span<byte> ephPubEncoding = stackalloc byte[1 + X25519PublicKeyParameters.KeySize];
                    ((X25519PublicKeyParameters)ephKp.Public).Encode(ephPubEncoding[1..]);
#else
                    byte[] ephPubEncoding = new byte[1 + X25519PublicKeyParameters.KeySize];
                    ((X25519PublicKeyParameters)ephKp.Public).Encode(ephPubEncoding, 1);
#endif
                    ephPubEncoding[0] = 0x40;

                    return EncryptSessionInfo(ecPubKey, sessionInfo, secret, ephPubEncoding, random);
                }
                else if (EdECObjectIdentifiers.id_X448.Equals(curveOid))
                {
                    X448KeyPairGenerator gen = new X448KeyPairGenerator();
                    gen.Init(new X448KeyGenerationParameters(random));

                    AsymmetricCipherKeyPair ephKp = gen.GenerateKeyPair();

                    X448Agreement agreement = new X448Agreement();
                    agreement.Init(ephKp.Private);

                    byte[] secret = new byte[agreement.AgreementSize];
                    agreement.CalculateAgreement(cryptoPublicKey, secret, 0);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    Span<byte> ephPubEncoding = stackalloc byte[1 + X448PublicKeyParameters.KeySize];
                    ((X448PublicKeyParameters)ephKp.Public).Encode(ephPubEncoding[1..]);
#else
                    byte[] ephPubEncoding = new byte[1 + X448PublicKeyParameters.KeySize];
                    ((X448PublicKeyParameters)ephKp.Public).Encode(ephPubEncoding, 1);
#endif
                    ephPubEncoding[0] = 0x40;

                    return EncryptSessionInfo(ecPubKey, sessionInfo, secret, ephPubEncoding, random);
                }
                else
                {
                    // Generate the ephemeral key pair
                    ECDomainParameters ecParams = ((ECPublicKeyParameters)cryptoPublicKey).Parameters;
                    ECKeyPairGenerator gen = new ECKeyPairGenerator();
                    gen.Init(new ECKeyGenerationParameters(ecParams, random));

                    AsymmetricCipherKeyPair ephKp = gen.GenerateKeyPair();

                    ECDHBasicAgreement agreement = new ECDHBasicAgreement();
                    agreement.Init(ephKp.Private);
                    BigInteger S = agreement.CalculateAgreement(cryptoPublicKey);
                    byte[] secret = BigIntegers.AsUnsignedByteArray(agreement.GetFieldSize(), S);

                    var q = ((ECPublicKeyParameters)ephKp.Public).Q;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    int encodedLength = q.GetEncodedLength(false);
                    Span<byte> ephPubEncoding = encodedLength <= 512
                        ? stackalloc byte[encodedLength]
                        : new byte[encodedLength];
                    q.EncodeTo(false, ephPubEncoding);
#else
                    byte[] ephPubEncoding = q.GetEncoded(false);
#endif

                    return EncryptSessionInfo(ecPubKey, sessionInfo, secret, ephPubEncoding, random);
                }
            }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            private byte[] EncryptSessionInfo(ECDHPublicBcpgKey ecPubKey, byte[] sessionInfo, byte[] secret,
                ReadOnlySpan<byte> ephPubEncoding, SecureRandom random)
#else
            private byte[] EncryptSessionInfo(ECDHPublicBcpgKey ecPubKey, byte[] sessionInfo, byte[] secret,
                byte[] ephPubEncoding, SecureRandom random)
#endif
            {
                var key = new KeyParameter(Rfc6637Utilities.CreateKey(pubKey.PublicKeyPacket, secret));

                IWrapper w = PgpUtilities.CreateWrapper(ecPubKey.SymmetricKeyAlgorithm);
                w.Init(true, new ParametersWithRandom(key, random));

                byte[] paddedSessionData = PgpPad.PadSessionData(sessionInfo, sessionKeyObfuscation);

                byte[] C = w.Wrap(paddedSessionData, 0, paddedSessionData.Length);
                byte[] VB = new MPInteger(new BigInteger(1, ephPubEncoding)).GetEncoded();

                byte[] rv = new byte[VB.Length + 1 + C.Length];

                Array.Copy(VB, 0, rv, 0, VB.Length);
                rv[VB.Length] = (byte)C.Length;
                Array.Copy(C, 0, rv, VB.Length + 1, C.Length);

                return rv;
            }

            private byte[][] ProcessSessionInfo(byte[] encryptedSessionInfo)
            {
                byte[][] data;

                switch (pubKey.Algorithm)
                {
                case PublicKeyAlgorithmTag.RsaEncrypt:
                case PublicKeyAlgorithmTag.RsaGeneral:
                    data = new byte[1][]{ ConvertToEncodedMpi(encryptedSessionInfo) };
                    break;
                case PublicKeyAlgorithmTag.ElGamalEncrypt:
                case PublicKeyAlgorithmTag.ElGamalGeneral:
                    int halfLength = encryptedSessionInfo.Length / 2;
                    byte[] b1 = new byte[halfLength];
                    byte[] b2 = new byte[halfLength];

                    Array.Copy(encryptedSessionInfo, 0, b1, 0, halfLength);
                    Array.Copy(encryptedSessionInfo, halfLength, b2, 0, halfLength);

                    data = new byte[2][]{
                    ConvertToEncodedMpi(b1),
                    ConvertToEncodedMpi(b2),
                };
                    break;
                case PublicKeyAlgorithmTag.ECDH:
                    data = new byte[1][]{ encryptedSessionInfo };
                    break;
                default:
                    throw new PgpException("unknown asymmetric algorithm: " + pubKey.Algorithm);
                }

                return data;
            }

            private static byte[] ConvertToEncodedMpi(byte[] encryptedSessionInfo)
            {
                try
                {
                    return new MPInteger(new BigInteger(1, encryptedSessionInfo)).GetEncoded();
                }
                catch (IOException e)
                {
                    throw new PgpException("Invalid MPI encoding: " + e.Message, e);
                }
            }

            public override void Encode(BcpgOutputStream pOut) =>
                new PublicKeyEncSessionPacket(pubKey.KeyId, pubKey.Algorithm, data).Encode(pOut);
        }

        private readonly List<EncMethod> methods = new List<EncMethod>();
        private readonly SymmetricKeyAlgorithmTag defAlgorithm;
        private readonly SecureRandom rand;

        public PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag encAlgorithm)
        {
            this.defAlgorithm = encAlgorithm;
            this.rand = CryptoServicesRegistrar.GetSecureRandom();
        }

        public PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag encAlgorithm, bool withIntegrityPacket)
        {
            this.defAlgorithm = encAlgorithm;
            this.withIntegrityPacket = withIntegrityPacket;
            this.rand = CryptoServicesRegistrar.GetSecureRandom();
        }

        /// <summary>Existing SecureRandom constructor.</summary>
        /// <param name="encAlgorithm">The symmetric algorithm to use.</param>
        /// <param name="random">Source of randomness.</param>
        public PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag encAlgorithm, SecureRandom random)
        {
            this.defAlgorithm = encAlgorithm;
            this.rand = random ?? throw new ArgumentNullException(nameof(random));
        }

        /// <summary>Creates a cipher stream which will have an integrity packet associated with it.</summary>
        public PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag encAlgorithm, bool withIntegrityPacket,
            SecureRandom random)
        {
            this.defAlgorithm = encAlgorithm;
            this.rand = random ?? throw new ArgumentNullException(nameof(random));
            this.withIntegrityPacket = withIntegrityPacket;
        }

        /// <summary>Base constructor.</summary>
        /// <param name="encAlgorithm">The symmetric algorithm to use.</param>
        /// <param name="random">Source of randomness.</param>
        /// <param name="oldFormat">PGP 2.6.x compatibility required.</param>
        public PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag encAlgorithm, SecureRandom random, bool oldFormat)
        {
            this.defAlgorithm = encAlgorithm;
            this.rand = random ?? throw new ArgumentNullException(nameof(random));
            this.oldFormat = oldFormat;
        }

        /// <summary>Add a PBE encryption method to the encrypted object.</summary>
        /// <remarks>
        /// Conversion of the passphrase characters to bytes is performed using Convert.ToByte(), which is
        /// the historical behaviour of the library (1.7 and earlier).
        /// </remarks>
        public void AddMethod(char[] passPhrase, HashAlgorithmTag s2kDigest)
        {
            var rawPassPhrase = PgpUtilities.EncodePassPhrase(passPhrase, utf8: false);

            ImplAddPbeMethod(rawPassPhrase, clearPassPhrase: true, s2kDigest, itCount: 0x60);
        }

        /// <summary>Add a PBE encryption method to the encrypted object.</summary>
        /// <remarks>
        /// The passphrase is encoded to bytes using UTF8 (Encoding.UTF8.GetBytes).
        /// </remarks>
        public void AddMethodUtf8(char[] passPhrase, HashAlgorithmTag s2kDigest)
        {
            var rawPassPhrase = PgpUtilities.EncodePassPhrase(passPhrase, utf8: true);

            ImplAddPbeMethod(rawPassPhrase, clearPassPhrase: true, s2kDigest, itCount: 0x60);
        }

        /// <summary>Add a PBE encryption method to the encrypted object.</summary>
        /// <remarks>
        /// Allows the caller to handle the encoding of the passphrase to bytes.
        /// </remarks>
        public void AddMethodRaw(byte[] rawPassPhrase, HashAlgorithmTag s2kDigest) =>
            ImplAddPbeMethod(rawPassPhrase, clearPassPhrase: false, s2kDigest, itCount: 0x60);

        /// <summary>Add a PBE encryption method to the encrypted object.</summary>
        /// <remarks>
        /// Conversion of the passphrase characters to bytes is performed using Convert.ToByte(), which is
        /// the historical behaviour of the library (1.7 and earlier).
        /// </remarks>
        public void AddMethod(char[] passPhrase, HashAlgorithmTag s2kDigest, int itCount)
        {
            var rawPassPhrase = PgpUtilities.EncodePassPhrase(passPhrase, utf8: false);

            ImplAddPbeMethod(rawPassPhrase, clearPassPhrase: true, s2kDigest, itCount);
        }

        /// <summary>Add a PBE encryption method to the encrypted object.</summary>
        /// <remarks>
        /// The passphrase is encoded to bytes using UTF8 (Encoding.UTF8.GetBytes).
        /// </remarks>
        public void AddMethodUtf8(char[] passPhrase, HashAlgorithmTag s2kDigest, int itCount)
        {
            var rawPassPhrase = PgpUtilities.EncodePassPhrase(passPhrase, utf8: true);

            ImplAddPbeMethod(rawPassPhrase, clearPassPhrase: true, s2kDigest, itCount);
        }

        /// <summary>Add a PBE encryption method to the encrypted object.</summary>
        /// <remarks>
        /// Allows the caller to handle the encoding of the passphrase to bytes.
        /// </remarks>
        public void AddMethodRaw(byte[] rawPassPhrase, HashAlgorithmTag s2kDigest, int itCount) =>
            ImplAddPbeMethod(rawPassPhrase, clearPassPhrase: false, s2kDigest, itCount);

        internal void ImplAddPbeMethod(byte[] rawPassPhrase, bool clearPassPhrase, HashAlgorithmTag s2kDigest,
            int itCount)
        {
            var s2k = S2k.GenerateSaltedAndIterated(rand, s2kDigest, itCount);
            var key = PgpUtilities.DoMakeKeyFromPassPhrase(defAlgorithm, s2k, rawPassPhrase, clearPassPhrase);
            var encMethod = new PbeMethod(defAlgorithm, s2k, key);
            methods.Add(encMethod);
        }

        /// <summary>Add a public key encrypted session key to the encrypted object.</summary>
        public void AddMethod(PgpPublicKey key) => AddMethod(key, sessionKeyObfuscation: true);

        public void AddMethod(PgpPublicKey key, bool sessionKeyObfuscation)
        {
            if (!key.IsEncryptionKey)
                throw new ArgumentException("passed in key not an encryption key!", nameof(key));

            methods.Add(new PubMethod(key, sessionKeyObfuscation));
        }

        private void AddCheckSum(byte[] sessionInfo)
        {
            Debug.Assert(sessionInfo != null);
            Debug.Assert(sessionInfo.Length >= 3);

            int check = 0;

            for (int i = 1; i < sessionInfo.Length - 2; i++)
            {
                check += sessionInfo[i];
            }

            sessionInfo[sessionInfo.Length - 2] = (byte)(check >> 8);
            sessionInfo[sessionInfo.Length - 1] = (byte)(check);
        }

        private byte[] CreateSessionInfo(SymmetricKeyAlgorithmTag algorithm, KeyParameter key)
        {
            int keyLength = key.KeyLength;
            byte[] sessionInfo = new byte[keyLength + 3];
            sessionInfo[0] = (byte)algorithm;
            key.CopyKeyTo(sessionInfo, 1, keyLength);
            AddCheckSum(sessionInfo);
            return sessionInfo;
        }

        /// <summary>
        /// <p>
        /// If buffer is non null stream assumed to be partial, otherwise the length will be used
        /// to output a fixed length packet.
        /// </p>
        /// <p>
        /// The stream created can be closed off by either calling Close()
        /// on the stream or Close() on the generator. Closing the returned
        /// stream does not close off the Stream parameter <c>outStr</c>.
        /// </p>
        /// </summary>
        private Stream Open(Stream outStr, long length, byte[] buffer)
        {
            if (cOut != null)
                throw new InvalidOperationException("generator already in open state");
            if (methods.Count == 0)
                throw new InvalidOperationException("No encryption methods specified");
            if (outStr == null)
                throw new ArgumentNullException(nameof(outStr));

            pOut = new BcpgOutputStream(outStr);

            KeyParameter key;

            if (methods.Count == 1)
            {
                if (methods[0] is PbeMethod pbeMethod)
                {
                    key = pbeMethod.GetKey();
                }
                else if (methods[0] is PubMethod pubMethod)
                {
                    key = PgpUtilities.MakeRandomKey(defAlgorithm, rand);

                    byte[] sessionInfo = CreateSessionInfo(defAlgorithm, key);

                    try
                    {
                        pubMethod.AddSessionInfo(sessionInfo, rand);
                    }
                    catch (Exception e)
                    {
                        throw new PgpException("exception encrypting session key", e);
                    }
                }
                else
                {
                    throw new InvalidOperationException();
                }

                methods[0].Encode(pOut);
            }
            else // multiple methods
            {
                key = PgpUtilities.MakeRandomKey(defAlgorithm, rand);
                byte[] sessionInfo = CreateSessionInfo(defAlgorithm, key);

                foreach (EncMethod m in methods)
                {
                    try
                    {
                        m.AddSessionInfo(sessionInfo, rand);
                    }
                    catch (Exception e)
                    {
                        throw new PgpException("exception encrypting session key", e);
                    }

                    m.Encode(pOut);
                }
            }

            string cName = PgpUtilities.GetSymmetricCipherName(defAlgorithm);
            if (cName == null)
                throw new PgpException("null cipher specified");

            try
            {
                if (withIntegrityPacket)
                {
                    cName += "/CFB/NoPadding";
                }
                else
                {
                    cName += "/OpenPGPCFB/NoPadding";
                }

                c = CipherUtilities.GetCipher(cName);

                // TODO Confirm the IV should be all zero bytes (not inLineIv - see below)
                byte[] iv = new byte[c.GetBlockSize()];
                c.Init(true, new ParametersWithRandom(new ParametersWithIV(key, iv), rand));

                if (buffer == null)
                {
                    //
                    // we have to Add block size + 2 for the Generated IV and + 1 + 22 if integrity protected
                    //
                    if (withIntegrityPacket)
                    {
                        pOut = new BcpgOutputStream(outStr, PacketTag.SymmetricEncryptedIntegrityProtected, length + c.GetBlockSize() + 2 + 1 + 22);
                        pOut.WriteByte(1);        // version number
                    }
                    else
                    {
                        pOut = new BcpgOutputStream(outStr, PacketTag.SymmetricKeyEncrypted, length + c.GetBlockSize() + 2, oldFormat);
                    }
                }
                else
                {
                    if (withIntegrityPacket)
                    {
                        pOut = new BcpgOutputStream(outStr, PacketTag.SymmetricEncryptedIntegrityProtected, buffer);
                        pOut.WriteByte(1);        // version number
                    }
                    else
                    {
                        pOut = new BcpgOutputStream(outStr, PacketTag.SymmetricKeyEncrypted, buffer);
                    }
                }

                int blockSize = c.GetBlockSize();
                byte[] inLineIv = new byte[blockSize + 2];
                rand.NextBytes(inLineIv, 0, blockSize);
                Array.Copy(inLineIv, inLineIv.Length - 4, inLineIv, inLineIv.Length - 2, 2);

                Stream myOut = cOut = new CipherStream(pOut, null, c);

                if (withIntegrityPacket)
                {
                    IDigest digest = PgpUtilities.CreateDigest(HashAlgorithmTag.Sha1);
                    myOut = digestOut = new DigestStream(myOut, null, digest);
                }

                myOut.Write(inLineIv, 0, inLineIv.Length);

                return new WrappedGeneratorStream(this, myOut);
            }
            catch (Exception e)
            {
                throw new PgpException("Exception creating cipher", e);
            }
        }

        /// <summary>
        /// <p>
        /// Return an output stream which will encrypt the data as it is written to it.
        /// </p>
        /// <p>
        /// The stream created can be closed off by either calling Close()
        /// on the stream or Close() on the generator. Closing the returned
        /// stream does not close off the Stream parameter <c>outStr</c>.
        /// </p>
        /// </summary>
        public Stream Open(Stream outStr, long length) => Open(outStr, length, buffer: null);

        /// <summary>
        /// <p>
        /// Return an output stream which will encrypt the data as it is written to it.
        /// The stream will be written out in chunks according to the size of the passed in buffer.
        /// </p>
        /// <p>
        /// The stream created can be closed off by either calling Close()
        /// on the stream or Close() on the generator. Closing the returned
        /// stream does not close off the Stream parameter <c>outStr</c>.
        /// </p>
        /// <p>
        /// <b>Note</b>: if the buffer is not a power of 2 in length only the largest power of 2
        /// bytes worth of the buffer will be used.
        /// </p>
        /// </summary>
        public Stream Open(Stream outStr, byte[] buffer) => Open(outStr, length: 0, buffer);

        [Obsolete("Dispose any opened Stream directly")]
        public void Close()
        {
            if (cOut != null)
            {
                // TODO Should this all be under the try/catch block?
                if (digestOut != null)
                {
                    //
                    // hand code a mod detection packet
                    //
                    var bOut = new BcpgOutputStream(digestOut, PacketTag.ModificationDetectionCode, length: 20);

                    // For clarity; really only required if using partial body lengths
                    bOut.Finish();
                    bOut.Flush();

                    byte[] dig = DigestUtilities.DoFinal(digestOut.WriteDigest);

                    cOut.Write(dig, 0, dig.Length);
                }

                cOut.Flush();

                try
                {
                    pOut.Write(c.DoFinal());
                    pOut.Finish();
                }
                catch (Exception e)
                {
                    throw new IOException(e.Message, e);
                }

                cOut = null;
                pOut = null;
            }
        }
    }
}
