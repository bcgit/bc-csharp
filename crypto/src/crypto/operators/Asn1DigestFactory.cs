using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Security;
using System;
using System.IO;


namespace Org.BouncyCastle.Crypto.Operators
{
    public class Asn1DigestFactory : IDigestFactory
    {

        public static Asn1DigestFactory Get(DerObjectIdentifier oid)
        {
            return new Asn1DigestFactory(DigestUtilities.GetDigest(oid), oid);          
        }

        public static Asn1DigestFactory Get(String mechanism)
        {
            DerObjectIdentifier oid = DigestUtilities.GetObjectIdentifier(mechanism);
            return new Asn1DigestFactory(DigestUtilities.GetDigest(oid), oid);
        }


        private IDigest digest;
        private DerObjectIdentifier oid;

        public Asn1DigestFactory(IDigest digest, DerObjectIdentifier oid)
        {
            this.digest = digest;
            this.oid = oid;
        }    

        public object AlgorithmDetails => new AlgorithmIdentifier(oid);

        public int DigestLength => digest.GetDigestSize();

        public IStreamCalculator CreateCalculator() => new DfDigestStream(digest);
        
    }


    internal class DfDigestStream : IStreamCalculator
    {

        private DigestSink stream;

        public DfDigestStream(IDigest digest)
        {          
            stream = new DigestSink(digest);
        }

        public Stream Stream => stream;

        public object GetResult()
        {
            byte[] result = new byte[stream.Digest.GetDigestSize()];
            stream.Digest.DoFinal(result, 0);
            return new SimpleBlockResult(result);
        }
      
    }

   

}
