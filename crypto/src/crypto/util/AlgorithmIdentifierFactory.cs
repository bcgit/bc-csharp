using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Kisa;
using Org.BouncyCastle.Asn1.Misc;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Ntt;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Utilities
{
    public class AlgorithmIdentifierFactory
    {
        public static readonly DerObjectIdentifier IDEA_CBC = MiscObjectIdentifiers.as_sys_sec_alg_ideaCBC;
        public static readonly DerObjectIdentifier CAST5_CBC = MiscObjectIdentifiers.cast5CBC;

        /**
         * Create an AlgorithmIdentifier for the passed in encryption algorithm.
         *
         * @param encryptionOID OID for the encryption algorithm
         * @param keySize key size in bits (-1 if unknown)
         * @param random SecureRandom to use for parameter generation.
         * @return a full AlgorithmIdentifier including parameters
         * @throws IllegalArgumentException if encryptionOID cannot be matched
         */
        public static AlgorithmIdentifier GenerateEncryptionAlgID(DerObjectIdentifier encryptionOID, int keySize, SecureRandom random)

        {
            if (encryptionOID.Equals(NistObjectIdentifiers.IdAes128Cbc) ||
                encryptionOID.Equals(NistObjectIdentifiers.IdAes192Cbc) ||
                encryptionOID.Equals(NistObjectIdentifiers.IdAes256Cbc) ||
                encryptionOID.Equals(NttObjectIdentifiers.IdCamellia128Cbc) ||
                encryptionOID.Equals(NttObjectIdentifiers.IdCamellia192Cbc) ||
                encryptionOID.Equals(NttObjectIdentifiers.IdCamellia256Cbc) ||
                encryptionOID.Equals(KisaObjectIdentifiers.IdSeedCbc))
            {
                byte[] iv = new byte[16];
                random.NextBytes(iv);

                return new AlgorithmIdentifier(encryptionOID, new DerOctetString(iv));
            }
            else if (encryptionOID.Equals(PkcsObjectIdentifiers.DesEde3Cbc) ||
                     encryptionOID.Equals(IDEA_CBC) ||
                     encryptionOID.Equals(OiwObjectIdentifiers.DesCbc))
            {
                byte[] iv = new byte[8];
                random.NextBytes(iv);

                return new AlgorithmIdentifier(encryptionOID, new DerOctetString(iv));
            }
            else if (encryptionOID.Equals(CAST5_CBC))
            {
                byte[] iv = new byte[8];
                random.NextBytes(iv);

                Cast5CbcParameters cbcParams = new Cast5CbcParameters(iv, keySize);

                return new AlgorithmIdentifier(encryptionOID, cbcParams);
            }
            else if (encryptionOID.Equals(PkcsObjectIdentifiers.rc4))
            {
                return new AlgorithmIdentifier(encryptionOID, DerNull.Instance);
            }
            else if (encryptionOID.Equals(PkcsObjectIdentifiers.RC2Cbc))
            {
                byte[] iv = new byte[8];
                random.NextBytes(iv);

                int parameterVersion = RC2CbcUtilities.GetParameterVersion(effectiveKeyBits: keySize);

                RC2CbcParameter cbcParams = new RC2CbcParameter(parameterVersion, iv);

                return new AlgorithmIdentifier(encryptionOID, cbcParams);
            }
            else
            {
                throw new InvalidOperationException("unable to match algorithm");
            }
        }
    }
}
