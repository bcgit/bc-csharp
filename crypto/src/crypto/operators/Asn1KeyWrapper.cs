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

namespace Org.BouncyCastle.Crypto.Operators
{

    public class KeyWrapperUtil
    {
        //
        // Provider 
        //
        private static readonly IDictionary providerMap = Platform.CreateHashtable();

        static KeyWrapperUtil()
        {
            providerMap["RSA/NONE/OAEPPADDING"] = new WrapperCreator(RsaOaepWrapper.Rsa_None_OaepPadding);
            providerMap["RSA/NONE/OAEPWITHSHA256ANDMGF1PADDING"] = new WrapperCreator(RsaOaepWrapper.Rsa_None_OaepWithSha256andMGF1Padding);          
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

        public static IKeyUnwrapper UnWrapperForName(string algorithm)
        {
            WrapperProvider provider = (WrapperProvider)providerMap[Strings.ToUpperCase(algorithm)];
            if (provider == null)
            {
                throw new ArgumentException("could not resolve " + algorithm + " to a KeyUnWrapper");
            }

            return (IKeyUnwrapper)provider.createWrapper();
        }
    }


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

        internal static object Rsa_None_OaepPadding()
        {
            return new RsaOaepWrapper(new Sha1Digest(),PkcsObjectIdentifiers.IdRsaesOaep);
        }

        internal static object Rsa_None_OaepWithSha256andMGF1Padding()
        {
            return new RsaOaepWrapper(new Sha256Digest(), PkcsObjectIdentifiers.IdRsaesOaep);
        }


        private readonly AlgorithmIdentifier algId;
        private readonly IAsymmetricBlockCipher engine;

        public RsaOaepWrapper(IDigest digest, DerObjectIdentifier digestOid)
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
