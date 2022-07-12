using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pqc.Crypto.Tests
{
    public class NistSecureRandom
        : SecureRandom
    {
        
        private byte[] seed;
        private byte[] personalization;
        private byte[] key;
        private byte[] v;
        int reseed_counuter = 1;

        /// <summary>
        /// Return a seeded FixedSecureRandom representing the result of processing a
        /// CMCE test seed with the CMCE RandomNumberGenerator.
        /// </summary>
        /// <param name="seed"> original CMCE seed</param>
        /// <param name="strength"> bit-strength of the RNG required.</param>
        /// <returns> a FixedSecureRandom containing the correct amount of seed material for use with Java.</returns>
        /// 
        public static FixedSecureRandom GetFixed(byte[] seed, int strength)
        {
            return GetFixed(seed,null, strength, strength / 8, strength / 8);
        }

        public static FixedSecureRandom GetFixed(byte[] seed, byte[] personalization, int strength, int discard, int size)
        {
            NistSecureRandom cmceRNG = new NistSecureRandom(seed, personalization);
            cmceRNG.Init(strength);
            byte[] burn = new byte[discard];
            cmceRNG.NextBytes(burn);
            if (discard != size)
            {
                burn = new byte[size];
            }
            cmceRNG.NextBytes(burn);
            FixedSecureRandom.Source[] source = {new FixedSecureRandom.Source(burn)};
            return new FixedSecureRandom(source);
        }


        public static FixedSecureRandom GetFixedNoDiscard(byte[] seed, int strength)
        {
            NistSecureRandom cmceRNG = new NistSecureRandom(seed, null);
            cmceRNG.Init(strength);
            byte[] burn = new byte[strength / 8];
            cmceRNG.NextBytes(burn);
            FixedSecureRandom.Source[] source = {new FixedSecureRandom.Source(burn)};
            return new FixedSecureRandom(source);
        }

        public NistSecureRandom(byte[] seed, byte[] personalization)
        {
            this.seed = seed;
            this.personalization = personalization;
            Init(256);
        }


        private void Init(int strength)
        {
            randombytes_init(seed, personalization, strength);
            reseed_counuter = 1;
        }

        public override void NextBytes(byte[] buf)
        {
            NextBytes(buf, 0, buf.Length);
        }

        public override void NextBytes(byte[] buf, int off, int len)
        {
            byte[] block = new byte[16];
            int i = 0;

            while (len > 0)
            {
                for (int j = 15; j >= 0; j--)
                {
                    if ((v[j] & 0xFF) == 0xff)
                    {
                        v[j] = 0x00;
                    }
                    else
                    {
                        v[j]++;
                        break;
                    }
                }

                AES256_ECB(key, v, block, 0);

                if (len > 15)
                {
                    Array.Copy(block, 0, buf, off + i, block.Length);
                    i += 16;
                    len -= 16;
                }
                else
                {
                    Array.Copy(block, 0, buf, off + i, len);
                    len = 0;
                }
            }

            AES256_CTR_DRBG_Update(null, key, v);
            reseed_counuter++;
        }


        private void AES256_ECB(byte[] key, byte[] ctr, byte[] buffer, int startPosition)
        {
            try
            {
                IBufferedCipher cipher = CipherUtilities.GetCipher("AES/ECB/NoPadding");
                cipher.Init(true, ParameterUtilities.CreateKeyParameter("AES", key));

                cipher.DoFinal(ctr, 0, ctr.Length, buffer, startPosition);
            }
            catch (Exception ex)
            {
                Console.Write(ex.StackTrace);
            }
        }


        private void AES256_CTR_DRBG_Update(byte[] entropy_input, byte[] key, byte[] v)
        {

            byte[] tmp = new byte[48];

            for (int i = 0; i < 3; i++)
            {
                //increment V
                for (int j = 15; j >= 0; j--)
                {
                    if ((v[j] & 0xFF) == 0xff)
                    {
                        v[j] = 0x00;
                    }
                    else
                    {
                        v[j]++;
                        break;
                    }
                }

                AES256_ECB(key, v, tmp, 16 * i);
            }

            if (entropy_input != null)
            {
                for (int i = 0; i < 48; i++)
                {
                    tmp[i] ^= entropy_input[i];
                }
            }

            Array.Copy(tmp, 0, key, 0, key.Length);
            Array.Copy(tmp, 32, v, 0, v.Length);


        }


        private void randombytes_init(byte[] entropyInput, byte[] personalization, int strength)
        {
            byte[] seedMaterial = new byte[48];

            Array.Copy(entropyInput, 0, seedMaterial, 0, seedMaterial.Length);
            if (personalization != null)
            {
                for (int i = 0; i < 48; i++)
                {
                    seedMaterial[i] ^= personalization[i];
                }
            }

            key = new byte[32];
            v = new byte[16];


            AES256_CTR_DRBG_Update(seedMaterial, key, v);

            reseed_counuter = 1;

        }
    }
}