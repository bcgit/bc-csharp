using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Nist;

namespace Org.BouncyCastle.Crypto.Operators
{
    public class Asn1KeyWrapper : IKeyWrapper
    {
        private X509Certificate cert;
        private string algorithm;
        private IKeyWrapper wrapper;

        public Asn1KeyWrapper(string algorithm, X509Certificate cert)
        {
            this.algorithm = algorithm;
            this.cert = cert;
            wrapper = KeyWrapperUtil.WrapperForName(algorithm);
        }

        public object AlgorithmDetails
        {
            get { return wrapper.AlgorithmDetails; }
        }

        public IBlockResult Wrap(byte[] keyData)
        {
            return wrapper.Wrap(keyData);
        }
    }

    internal class KeyWrapperUtil
    {
        //
        // Provider 
        //
        private static readonly IDictionary providerMap = Platform.CreateHashtable();

        static KeyWrapperUtil()
        {
            providerMap["RSA/NONE/OAEPWITHSHA1ANDMGF1PADDING"] = new WrapperCreator(RsaOaepWrapper.Rsa_Sha1_Oaep);
            providerMap["RSA/NONE/OAEPWITHSHA224ANDMGF1PADDING"] = new WrapperCreator(RsaOaepWrapper.Rsa_Sha224_Oaep);
            providerMap["RSA/NONE/OAEPWITHSHA256ANDMGF1PADDING"] = new WrapperCreator(RsaOaepWrapper.Rsa_Sha256_Oaep);
            providerMap["RSA/NONE/OAEPWITHSHA384ANDMGF1PADDING"] = new WrapperCreator(RsaOaepWrapper.Rsa_Sha384_Oaep);
            providerMap["RSA/NONE/OAEPWITHSHA512ANDMGF1PADDING"] = new WrapperCreator(RsaOaepWrapper.Rsa_Sha512_Oaep);
        }

        public static IKeyWrapper WrapperForName(string algorithm)
        {
            WrapperProvider provider = (WrapperProvider)providerMap[Strings.ToUpperCase(algorithm)];

            if (provider == null)
            {
                throw new ArgumentException("could not resolve " + algorithm + " to a KeyWrapper");
            }

            return (IKeyWrapper)provider.createWrapper();
        }

        public static IKeyUnwrapper UnwrapperForName(string algorithm)
        {
            WrapperProvider provider = (WrapperProvider)providerMap[Strings.ToUpperCase(algorithm)];
            if (provider == null)
            {
                throw new ArgumentException("could not resolve " + algorithm + " to a KeyUnwrapper");
            }

            return (IKeyUnwrapper)provider.createWrapper();
        }
    }

    internal delegate object WrapperCreatorDelegate();

    /// <summary>
    /// Wraps delegate and implements the WrapperProvider Interface.
    /// </summary>
    internal class WrapperCreator : WrapperProvider
    {
        private readonly WrapperCreatorDelegate creator;

        public WrapperCreator(WrapperCreatorDelegate creator)
        {
            this.creator = creator;
        }

        public object createWrapper()
        {
            return this.creator.Invoke();
        }
    }

    internal interface WrapperProvider
    {
        object createWrapper();
    }

    internal class RsaOaepWrapper : IKeyWrapper, IKeyUnwrapper
    {
        internal static object Rsa_Sha1_Oaep()
        {
            return new RsaOaepWrapper(OiwObjectIdentifiers.IdSha1, new Sha1Digest());
        }

        internal static object Rsa_Sha224_Oaep()
        {
            return new RsaOaepWrapper(NistObjectIdentifiers.IdSha224, new Sha224Digest());
        }

        internal static object Rsa_Sha256_Oaep()
        {
            return new RsaOaepWrapper(NistObjectIdentifiers.IdSha256, new Sha256Digest());
        }

        internal static object Rsa_Sha384_Oaep()
        {
            return new RsaOaepWrapper(NistObjectIdentifiers.IdSha384, new Sha384Digest());
        }

        internal static object Rsa_Sha512_Oaep()
        {
            return new RsaOaepWrapper(NistObjectIdentifiers.IdSha512, new Sha512Digest());
        }

        private readonly AlgorithmIdentifier algId;
        private readonly IAsymmetricBlockCipher engine;

        public RsaOaepWrapper(DerObjectIdentifier digestOid, IDigest digest)
        {
            AlgorithmIdentifier digestAlgId = new AlgorithmIdentifier(digestOid, DerNull.Instance);

            this.algId = new AlgorithmIdentifier(
                PkcsObjectIdentifiers.IdRsaesOaep,
                new RsaesOaepParameters(
                    digestAlgId,
                    new AlgorithmIdentifier(PkcsObjectIdentifiers.IdMgf1, digestAlgId),
                    RsaesOaepParameters.DefaultPSourceAlgorithm));
            this.engine = new OaepEncoding(new RsaBlindedEngine());
        }

        public object AlgorithmDetails
        {
            get
            {
                return algId;
            }
        }

        public IBlockResult Unwrap(byte[] cipherText, int offset, int length)
        {
            return new SimpleBlockResult(engine.ProcessBlock(cipherText, offset, length));
        }

        public IBlockResult Wrap(byte[] keyData)
        {
            return new SimpleBlockResult(engine.ProcessBlock(keyData, 0, keyData.Length));
        }
    }
}
