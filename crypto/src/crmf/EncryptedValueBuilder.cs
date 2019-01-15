using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Crmf;
using System.IO;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Crmf
{
    public class EncryptedValueBuilder
    {
        private IKeyWrapper wrapper;
        private ICipherBuilderWithKey encryptor;
        private EncryptedValuePadder padder;

        /**
         * Create a builder that makes EncryptedValue structures.
         *
         * @param wrapper a wrapper for key used to encrypt the actual data contained in the EncryptedValue.
         * @param encryptor  an output encryptor to encrypt the actual data contained in the EncryptedValue. 
         */
        public EncryptedValueBuilder(IKeyWrapper wrapper, ICipherBuilderWithKey encryptor) : this(wrapper, encryptor, null)
        {
        }

        /**
         * Create a builder that makes EncryptedValue structures with fixed length blocks padded using the passed in padder.
         *
         * @param wrapper a wrapper for key used to encrypt the actual data contained in the EncryptedValue.
         * @param encryptor  an output encryptor to encrypt the actual data contained in the EncryptedValue.
         * @param padder a padder to ensure that the EncryptedValue created will always be a constant length.
         */
        public EncryptedValueBuilder(IKeyWrapper wrapper, ICipherBuilderWithKey encryptor, EncryptedValuePadder padder)
        {
            this.wrapper = wrapper;
            this.encryptor = encryptor;
            this.padder = padder;
        }

        /**
         * Build an EncryptedValue structure containing the passed in pass phrase.
         *
         * @param revocationPassphrase  a revocation pass phrase.
         * @return an EncryptedValue containing the encrypted pass phrase.
         * @throws CrmfException on a failure to encrypt the data, or wrap the symmetric key for this value.
         */
        public EncryptedValue Build(char[] revocationPassphrase)
        {
            return encryptData(padData(Strings.ToUtf8ByteArray(revocationPassphrase)));
        }

        /**
         * Build an EncryptedValue structure containing the certificate contained in
         * the passed in holder.
         *
         * @param holder  a holder containing a certificate.
         * @return an EncryptedValue containing the encrypted certificate.
         * @throws CrmfException on a failure to encrypt the data, or wrap the symmetric key for this value.
         */
        public EncryptedValue Build(X509Certificate holder)
        {
            try
            {
                return encryptData(padData(holder.GetEncoded()));
            }
            catch (IOException e)
            {
                throw new CrmfException("cannot encode certificate: " + e.Message, e);
            }
        }

        /**
         * Build an EncryptedValue structure containing the private key contained in
         * the passed info structure.
         *
         * @param privateKeyInfo  a PKCS#8 private key info structure.
         * @return an EncryptedValue containing an EncryptedPrivateKeyInfo structure.
         * @throws CrmfException on a failure to encrypt the data, or wrap the symmetric key for this value.
         */
        public EncryptedValue Build(PrivateKeyInfo privateKeyInfo)
        {
            Pkcs8EncryptedPrivateKeyInfoBuilder encInfoBldr = new Pkcs8EncryptedPrivateKeyInfoBuilder(privateKeyInfo);

            AlgorithmIdentifier intendedAlg = privateKeyInfo.PrivateKeyAlgorithm;
            AlgorithmIdentifier symmAlg = (AlgorithmIdentifier)encryptor.AlgorithmDetails;
            DerBitString encSymmKey;

            try
            {
                Pkcs8EncryptedPrivateKeyInfo encInfo = encInfoBldr.Build(encryptor);

                encSymmKey = new DerBitString(wrapper.Wrap(((KeyParameter)encryptor.Key).GetKey()).Collect());

                AlgorithmIdentifier keyAlg = (AlgorithmIdentifier)wrapper.AlgorithmDetails;
                Asn1OctetString valueHint = null;

                return new EncryptedValue(intendedAlg, symmAlg, encSymmKey, keyAlg, valueHint, new DerBitString(encInfo.GetEncryptedData()));
            }
            catch (Exception e)
            {
                throw new CrmfException("cannot wrap key: " + e.Message, e);
            }
        }

        private EncryptedValue encryptData(byte[] data)
        {
            MemoryOutputStream bOut = new MemoryOutputStream();

            Stream eOut = encryptor.BuildCipher(bOut).Stream;

            try
            {
                eOut.Write(data, 0, data.Length);

                eOut.Close();
            }
            catch (IOException e)
            {
                throw new CrmfException("cannot process data: " + e.Message, e);
            }

            AlgorithmIdentifier intendedAlg = null;
            AlgorithmIdentifier symmAlg = (AlgorithmIdentifier)encryptor.AlgorithmDetails;
            DerBitString encSymmKey;

            try
            {
                encSymmKey = new DerBitString(wrapper.Wrap(((KeyParameter)encryptor.Key).GetKey()).Collect());
            }
            catch (Exception e)
            {
                throw new CrmfException("cannot wrap key: " + e.Message, e);
            }

            AlgorithmIdentifier keyAlg = (AlgorithmIdentifier)wrapper.AlgorithmDetails;
            Asn1OctetString valueHint = null;
            DerBitString encValue = new DerBitString(bOut.ToArray());

            return new EncryptedValue(intendedAlg, symmAlg, encSymmKey, keyAlg, valueHint, encValue);
        }

        private byte[] padData(byte[] data)
        {
            if (padder != null)
            {
                return padder.GetPaddedData(data);
            }

            return data;
        }
    }
}
