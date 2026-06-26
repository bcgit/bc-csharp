using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Kisa;
using Org.BouncyCastle.Asn1.Misc;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Ntt;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Crypto.Utilities
{
    // TODO[api] Make static
    public class CipherFactory
    {
        private CipherFactory()
        {
        }

        public static object CreateContentCipher(bool forEncryption, ICipherParameters encKey,
            AlgorithmIdentifier encryptionAlgID)
        {
            DerObjectIdentifier encAlgOid = encryptionAlgID.Algorithm;

            if (PkcsObjectIdentifiers.rc4.Equals(encAlgOid))
            {
                var rc4Engine = new RC4Engine();
                rc4Engine.Init(forEncryption, encKey);
                return rc4Engine;
            }

            BufferedBlockCipher cipher = CreateCipher(encAlgOid);
            Asn1Object sParams = encryptionAlgID.Parameters.ToAsn1Object();

            if (X509Utilities.IsAbsentParameters(sParams))
            {
                if (encAlgOid.Equals(PkcsObjectIdentifiers.DesEde3Cbc) ||
                    encAlgOid.Equals(AlgorithmIdentifierFactory.IDEA_CBC) ||
                    encAlgOid.Equals(AlgorithmIdentifierFactory.CAST5_CBC))
                {
                    cipher.Init(forEncryption, new ParametersWithIV(encKey, new byte[8]));
                }
                else
                {
                    cipher.Init(forEncryption, encKey);
                }
            }
            else
            {
                if (encAlgOid.Equals(PkcsObjectIdentifiers.DesEde3Cbc) ||
                    encAlgOid.Equals(AlgorithmIdentifierFactory.IDEA_CBC) ||
                    encAlgOid.Equals(NistObjectIdentifiers.IdAes128Cbc) ||
                    encAlgOid.Equals(NistObjectIdentifiers.IdAes192Cbc) ||
                    encAlgOid.Equals(NistObjectIdentifiers.IdAes256Cbc) ||
                    encAlgOid.Equals(NttObjectIdentifiers.IdCamellia128Cbc) ||
                    encAlgOid.Equals(NttObjectIdentifiers.IdCamellia192Cbc) ||
                    encAlgOid.Equals(NttObjectIdentifiers.IdCamellia256Cbc) ||
                    encAlgOid.Equals(KisaObjectIdentifiers.IdSeedCbc) ||
                    encAlgOid.Equals(OiwObjectIdentifiers.DesCbc))
                {
                    cipher.Init(forEncryption, new ParametersWithIV(encKey, Asn1OctetString.GetInstance(sParams).GetOctets()));
                }
                else if (encAlgOid.Equals(AlgorithmIdentifierFactory.CAST5_CBC))
                {
                    Cast5CbcParameters cbcParams = Cast5CbcParameters.GetInstance(sParams);

                    cipher.Init(forEncryption, new ParametersWithIV(encKey, cbcParams.GetIV()));
                }
                else if (encAlgOid.Equals(PkcsObjectIdentifiers.RC2Cbc))
                {
                    var rc2CbcParameter = RC2CbcParameter.GetInstance(sParams);
                    int effectiveKeyBits = RC2CbcUtilities.GetEffectiveKeyBits(rc2CbcParameter);
                    var rc2Parameters = new RC2Parameters(((KeyParameter)encKey).GetKey(), effectiveKeyBits);

                    cipher.Init(forEncryption, new ParametersWithIV(rc2Parameters, rc2CbcParameter.IV.GetOctets()));
                }
                else
                {
                    throw new InvalidOperationException("cannot match parameters");
                }
            }

            return cipher;
        }

        private static BufferedBlockCipher CreateCipher(DerObjectIdentifier encAlgOid)
        {
            IBlockCipherMode cipher;

            if (NistObjectIdentifiers.IdAes128Cbc.Equals(encAlgOid) ||
                NistObjectIdentifiers.IdAes192Cbc.Equals(encAlgOid) ||
                NistObjectIdentifiers.IdAes256Cbc.Equals(encAlgOid))
            {
                cipher = new CbcBlockCipher(AesUtilities.CreateEngine());
            }
            else if (NttObjectIdentifiers.IdCamellia128Cbc.Equals(encAlgOid) ||
                     NttObjectIdentifiers.IdCamellia192Cbc.Equals(encAlgOid) ||
                     NttObjectIdentifiers.IdCamellia256Cbc.Equals(encAlgOid))
            {
                cipher = new CbcBlockCipher(new CamelliaEngine());
            }
            else if (AlgorithmIdentifierFactory.IDEA_CBC.Equals(encAlgOid))
            {
                cipher = new CbcBlockCipher(new IdeaEngine());
            }
            else if (KisaObjectIdentifiers.IdSeedCbc.Equals(encAlgOid))
            {
                cipher = new CbcBlockCipher(new SeedEngine());
            }
            else if (PkcsObjectIdentifiers.DesEde3Cbc.Equals(encAlgOid))
            {
                cipher = new CbcBlockCipher(new DesEdeEngine());
            }
            else if (OiwObjectIdentifiers.DesCbc.Equals(encAlgOid))
            {
                cipher = new CbcBlockCipher(new DesEngine());
            }
            else if (PkcsObjectIdentifiers.RC2Cbc.Equals(encAlgOid))
            {
                cipher = new CbcBlockCipher(new RC2Engine());
            }
            else if (MiscObjectIdentifiers.cast5CBC.Equals(encAlgOid))
            {
                cipher = new CbcBlockCipher(new Cast5Engine());
            }
            else
            {
                throw new InvalidOperationException("cannot recognise cipher: " + encAlgOid);
            }

            return new PaddedBufferedBlockCipher(cipher, new Pkcs7Padding());
        }
    }
}
