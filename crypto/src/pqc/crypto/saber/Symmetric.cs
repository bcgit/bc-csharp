using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Pqc.Crypto.Saber;

public abstract class Symmetric
{

    internal abstract void Hash_h(byte[] output, byte[] input, int outputOffset);

    internal abstract void Hash_g(byte[] output, byte[] input);

    internal abstract void Prf(byte[] output, byte[] input, int inLen, int outputLen);

    protected internal class ShakeSymmetric
        : Symmetric
    {

        private readonly Sha3Digest sha3Digest256;
        private readonly Sha3Digest sha3Digest512;
        private readonly IXof shakeDigest;

        internal ShakeSymmetric()
        {
            shakeDigest = new ShakeDigest(128);
            sha3Digest256 = new Sha3Digest(256);
            sha3Digest512 = new Sha3Digest(512);
        }

        internal override void Hash_h(byte[] output, byte[] input, int outputOffset)
        {
            sha3Digest256.BlockUpdate(input, 0, input.Length);
            sha3Digest256.DoFinal(output, outputOffset);
        }

        internal override void Hash_g(byte[] output, byte[] input)
        {
            sha3Digest512.BlockUpdate(input, 0, input.Length);
            sha3Digest512.DoFinal(output, 0);
        }

        internal override void Prf(byte[] output, byte[] input, int inLen, int outputLen)
        {
            shakeDigest.Reset();
            shakeDigest.BlockUpdate(input, 0, inLen);
            shakeDigest.OutputFinal(output, 0, outputLen);
        }


    }
    internal class AesSymmetric
        : Symmetric
    {

        private readonly Sha256Digest sha256Digest;
        private readonly Sha512Digest sha512Digest;

        private readonly SicBlockCipher cipher;


        protected internal AesSymmetric()
        {
            sha256Digest = new Sha256Digest();
            sha512Digest = new Sha512Digest();
            cipher = new SicBlockCipher(AesUtilities.CreateEngine());
        }
        
        internal override void Hash_h(byte[] output, byte[] input, int outputOffset)
        {
            sha256Digest.BlockUpdate(input, 0, input.Length);
            sha256Digest.DoFinal(output, outputOffset);
        }

        internal override void Hash_g(byte[] output, byte[] input)
        {
            sha512Digest.BlockUpdate(input, 0, input.Length);
            sha512Digest.DoFinal(output, 0);
        }

        internal override void Prf(byte[] output, byte[] input, int inLen, int outputLen)
        {
            ParametersWithIV kp = new ParametersWithIV(new KeyParameter(input, 0, inLen), new byte[16]);
            cipher.Init(true, kp);
            byte[] buf = new byte[outputLen];   // TODO: there might be a more efficient way of doing this...
            for (int i = 0; i < outputLen; i+= 16)
            {
                cipher.ProcessBlock(buf, i, output, i);
            }
        }


    }

}