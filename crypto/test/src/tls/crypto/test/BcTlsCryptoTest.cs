using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Tls.Tests;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Crypto.Tests
{
    [TestFixture]
    public class BcTlsCryptoTest
    {
        private static readonly byte[] ClientHello = Hex("01 00 00 c0 03 03 cb 34 ec b1 e7 81 63"
            + "ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62 83"
            + "02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b"
            + "00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00"
            + "12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23"
            + "00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2"
            + "3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a"
            + "af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03"
            + "02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06"
            + "02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01");
        private static readonly byte[] ServerHello = Hex("02 00 00 56 03 03 a6 af 06 a4 12 18 60"
            + "dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e"
            + "d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 c9 82 88"
            + "76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1"
            + "dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04");
        private static readonly byte[] EncryptedExtensions = Hex("08 00 00 24 00 22 00 0a 00 14 00"
            + "12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 1c"
            + "00 02 40 01 00 00 00 00");
        private static readonly byte[] Certificate = Hex("0b 00 01 b9 00 00 01 b5 00 01 b0 30 82"
            + "01 ac 30 82 01 15 a0 03 02 01 02 02 01 02 30 0d 06 09 2a 86 48"
            + "86 f7 0d 01 01 0b 05 00 30 0e 31 0c 30 0a 06 03 55 04 03 13 03"
            + "72 73 61 30 1e 17 0d 31 36 30 37 33 30 30 31 32 33 35 39 5a 17"
            + "0d 32 36 30 37 33 30 30 31 32 33 35 39 5a 30 0e 31 0c 30 0a 06"
            + "03 55 04 03 13 03 72 73 61 30 81 9f 30 0d 06 09 2a 86 48 86 f7"
            + "0d 01 01 01 05 00 03 81 8d 00 30 81 89 02 81 81 00 b4 bb 49 8f"
            + "82 79 30 3d 98 08 36 39 9b 36 c6 98 8c 0c 68 de 55 e1 bd b8 26"
            + "d3 90 1a 24 61 ea fd 2d e4 9a 91 d0 15 ab bc 9a 95 13 7a ce 6c"
            + "1a f1 9e aa 6a f9 8c 7c ed 43 12 09 98 e1 87 a8 0e e0 cc b0 52"
            + "4b 1b 01 8c 3e 0b 63 26 4d 44 9a 6d 38 e2 2a 5f da 43 08 46 74"
            + "80 30 53 0e f0 46 1c 8c a9 d9 ef bf ae 8e a6 d1 d0 3e 2b d1 93"
            + "ef f0 ab 9a 80 02 c4 74 28 a6 d3 5a 8d 88 d7 9f 7f 1e 3f 02 03"
            + "01 00 01 a3 1a 30 18 30 09 06 03 55 1d 13 04 02 30 00 30 0b 06"
            + "03 55 1d 0f 04 04 03 02 05 a0 30 0d 06 09 2a 86 48 86 f7 0d 01"
            + "01 0b 05 00 03 81 81 00 85 aa d2 a0 e5 b9 27 6b 90 8c 65 f7 3a"
            + "72 67 17 06 18 a5 4c 5f 8a 7b 33 7d 2d f7 a5 94 36 54 17 f2 ea"
            + "e8 f8 a5 8c 8f 81 72 f9 31 9c f3 6b 7f d6 c5 5b 80 f2 1a 03 01"
            + "51 56 72 60 96 fd 33 5e 5e 67 f2 db f1 02 70 2e 60 8c ca e6 be"
            + "c1 fc 63 a4 2a 99 be 5c 3e b7 10 7c 3c 54 e9 b9 eb 2b d5 20 3b"
            + "1c 3b 84 e0 a8 b2 f7 59 40 9b a3 ea c9 d9 1d 40 2d cc 0c c8 f8"
            + "96 12 29 ac 91 87 b4 2b 4d e1 00 00");
        private static readonly byte[] CertificateVerify = Hex("0f 00 00 84 08 04 00 80 5a 74 7c"
            + "5d 88 fa 9b d2 e5 5a b0 85 a6 10 15 b7 21 1f 82 4c d4 84 14 5a"
            + "b3 ff 52 f1 fd a8 47 7b 0b 7a bc 90 db 78 e2 d3 3a 5c 14 1a 07"
            + "86 53 fa 6b ef 78 0c 5e a2 48 ee aa a7 85 c4 f3 94 ca b6 d3 0b"
            + "be 8d 48 59 ee 51 1f 60 29 57 b1 54 11 ac 02 76 71 45 9e 46 44"
            + "5c 9e a5 8c 18 1e 81 8e 95 b8 c3 fb 0b f3 27 84 09 d3 be 15 2a"
            + "3d a5 04 3e 06 3d da 65 cd f5 ae a2 0d 53 df ac d4 2f 74 f3");
        private static readonly byte[] ServerFinished = Hex("14 00 00 20 9b 9b 14 1d 90 63 37 fb d2 cb"
            + "dc e7 1d f4 de da 4a b4 2c 30 95 72 cb 7f ff ee 54 54 b7 8f 07"
            + "18");
        private static readonly byte[] ClientFinished = Hex("14 00 00 20 a8 ec 43 6d 67 76 34 ae 52 5a"
            + "c1 fc eb e1 1a 03 9e c1 76 94 fa c6 e9 85 27 b6 42 f2 ed d5 ce"
            + "61");

        private readonly TlsCrypto m_crypto = new BcTlsCrypto(new SecureRandom());

        protected TlsCredentialedSigner LoadCredentialedSigner(TlsCryptoParameters cryptoParams, string resource,
            SignatureAndHashAlgorithm signatureAndHashAlgorithm)
        {
            return TlsTestUtilities.LoadSignerCredentials(cryptoParams, m_crypto,
                new string[]{ "x509-server-" + resource + ".pem" }, "x509-server-key-" + resource + ".pem",
                signatureAndHashAlgorithm);
        }

        protected TlsCredentialedSigner LoadCredentialedSignerLegacy(TlsCryptoParameters cryptoParams,
            short signatureAlgorithm)
        {
            switch (signatureAlgorithm)
            {
            case SignatureAlgorithm.dsa:
                return LoadCredentialedSigner(cryptoParams, "dsa", null);
            case SignatureAlgorithm.ecdsa:
                return LoadCredentialedSigner(cryptoParams, "ecdsa", null);
            case SignatureAlgorithm.rsa:
                return LoadCredentialedSigner(cryptoParams, "rsa-sign", null);
            default:
                return null;
            }
        }

        protected TlsCredentialedSigner LoadCredentialedSigner12(TlsCryptoParameters cryptoParams,
            SignatureAndHashAlgorithm signatureAndHashAlgorithm)
        {
            switch (signatureAndHashAlgorithm.Signature)
            {
            case SignatureAlgorithm.dsa:
                return LoadCredentialedSigner(cryptoParams, "dsa", signatureAndHashAlgorithm);
            case SignatureAlgorithm.ecdsa:
                return LoadCredentialedSigner(cryptoParams, "ecdsa", signatureAndHashAlgorithm);
            case SignatureAlgorithm.ed25519:
                return LoadCredentialedSigner(cryptoParams, "ed25519", signatureAndHashAlgorithm);
            case SignatureAlgorithm.ed448:
                return LoadCredentialedSigner(cryptoParams, "ed448", signatureAndHashAlgorithm);
            case SignatureAlgorithm.rsa_pss_pss_sha256:
                return LoadCredentialedSigner(cryptoParams, "rsa_pss_256", signatureAndHashAlgorithm);
            case SignatureAlgorithm.rsa_pss_pss_sha384:
                return LoadCredentialedSigner(cryptoParams, "rsa_pss_384", signatureAndHashAlgorithm);
            case SignatureAlgorithm.rsa_pss_pss_sha512:
                return LoadCredentialedSigner(cryptoParams, "rsa_pss_512", signatureAndHashAlgorithm);
            case SignatureAlgorithm.rsa:
            case SignatureAlgorithm.rsa_pss_rsae_sha256:
            case SignatureAlgorithm.rsa_pss_rsae_sha384:
            case SignatureAlgorithm.rsa_pss_rsae_sha512:
                return LoadCredentialedSigner(cryptoParams, "rsa-sign", signatureAndHashAlgorithm);

            // TODO[draft-smyshlyaev-tls12-gost-suites-10] Add test resources for these
            case SignatureAlgorithm.gostr34102012_256:
            case SignatureAlgorithm.gostr34102012_512:

            default:
                return null;
            }
        }

        protected TlsCredentialedSigner LoadCredentialedSigner13(TlsCryptoParameters cryptoParams, int signatureScheme)
        {
            SignatureAndHashAlgorithm signatureAndHashAlgorithm = SignatureScheme.GetSignatureAndHashAlgorithm(
                signatureScheme);

            switch (signatureScheme)
            {
            case SignatureScheme.ecdsa_secp256r1_sha256:
                return LoadCredentialedSigner(cryptoParams, "ecdsa", signatureAndHashAlgorithm);
            case SignatureScheme.ed25519:
                return LoadCredentialedSigner(cryptoParams, "ed25519", signatureAndHashAlgorithm);
            case SignatureScheme.ed448:
                return LoadCredentialedSigner(cryptoParams, "ed448", signatureAndHashAlgorithm);
            case SignatureScheme.rsa_pss_pss_sha256:
                return LoadCredentialedSigner(cryptoParams, "rsa_pss_256", signatureAndHashAlgorithm);
            case SignatureScheme.rsa_pss_pss_sha384:
                return LoadCredentialedSigner(cryptoParams, "rsa_pss_384", signatureAndHashAlgorithm);
            case SignatureScheme.rsa_pss_pss_sha512:
                return LoadCredentialedSigner(cryptoParams, "rsa_pss_512", signatureAndHashAlgorithm);
            case SignatureScheme.rsa_pss_rsae_sha256:
            case SignatureScheme.rsa_pss_rsae_sha384:
            case SignatureScheme.rsa_pss_rsae_sha512:
                return LoadCredentialedSigner(cryptoParams, "rsa-sign", signatureAndHashAlgorithm);

            // TODO[tls] Add test resources for these
            case SignatureScheme.ecdsa_brainpoolP256r1tls13_sha256:
            case SignatureScheme.ecdsa_brainpoolP384r1tls13_sha384:
            case SignatureScheme.ecdsa_brainpoolP512r1tls13_sha512:
            case SignatureScheme.ecdsa_secp384r1_sha384:
            case SignatureScheme.ecdsa_secp521r1_sha512:
            case SignatureScheme.sm2sig_sm3:

            default:
                return null;
            }
        }

        [Test]
        public void TestDHDomain()
        {
            if (!m_crypto.HasDHAgreement())
                return;

            for (int namedGroup = 256; namedGroup < 512; ++namedGroup)
            {
                if (!NamedGroup.RefersToASpecificFiniteField(namedGroup) || !m_crypto.HasNamedGroup(namedGroup))
                    continue;

                ImplTestDHDomain(new TlsDHConfig(namedGroup, false));
                ImplTestDHDomain(new TlsDHConfig(namedGroup, true));
            }

            var groups = new TestTlsDHGroupVerifier().Groups;
            foreach (DHGroup dhGroup in groups)
            {
                BigInteger p = dhGroup.P, g = dhGroup.G;

                /*
                 * DefaultTlsDHGroupVerifier default groups are configured from DHStandardGroups, so
                 * we expect to recover the exact instance here.
                 */
                Assert.AreSame(dhGroup, TlsDHUtilities.GetStandardGroupForDHParameters(p, g));

                int namedGroup = TlsDHUtilities.GetNamedGroupForDHParameters(p, g);

                // Already tested the named groups
                if (NamedGroup.RefersToASpecificFiniteField(namedGroup))
                    continue;

                ImplTestDHDomain(new TlsDHConfig(dhGroup));
            }
        }

        [Test]
        public void TestECDomain()
        {
            if (!m_crypto.HasECDHAgreement())
                return;

            for (int namedGroup = 0; namedGroup < 256; ++namedGroup)
            {
                if (!NamedGroup.RefersToAnECDHCurve(namedGroup) || !m_crypto.HasNamedGroup(namedGroup))
                    continue;

                ImplTestECDomain(new TlsECConfig(namedGroup));
            }
        }

        [Test]
        public void TestHkdf()
        {
            /*
             * Test vectors drawn from the server-side calculations of example handshake trace in RFC 8448, section 3.
             */

            int hash = CryptoHashAlgorithm.sha256;
            int hashLen = TlsCryptoUtilities.GetHashOutputSize(hash);

            TlsSecret init = m_crypto.HkdfInit(hash), early, handshake, master, c_hs_t, s_hs_t, c_ap_t, s_ap_t, exp_master, res_master;

            TlsHash prfHash = m_crypto.CreateHash(hash);

            byte[] emptyTranscriptHash = GetCurrentHash(prfHash);
            Expect(emptyTranscriptHash, "e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24 27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55");

            // {server}  extract secret "early":
            {
                TlsSecret ikm = m_crypto.HkdfInit(hash);
                early = init.HkdfExtract(hash, ikm);
                Expect(early, "33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c e2 10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a");
            }

            // {server}  derive secret for handshake "tls13 derived":
            {
                string label = "derived";
                handshake = TlsCryptoUtilities.HkdfExpandLabel(early, hash, label, emptyTranscriptHash, hashLen);
                Expect(handshake, "6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba b6 97 16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba");
            }

            // {server}  extract secret "handshake":
            {
                TlsSecret ikm = m_crypto.CreateSecret(
                    Hex("8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d 35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d"));
                handshake = handshake.HkdfExtract(hash, ikm);
                Expect(handshake, "1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b 01 04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac");
            }

            prfHash.Update(ClientHello, 0, ClientHello.Length);
            prfHash.Update(ServerHello, 0, ServerHello.Length);

            byte[] serverHelloTranscriptHash = GetCurrentHash(prfHash);
            Expect(serverHelloTranscriptHash, "86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8");

            // {server}  derive secret "tls13 c hs traffic":
            {
                string label = "c hs traffic";
                c_hs_t = TlsCryptoUtilities.HkdfExpandLabel(handshake, hash, label, serverHelloTranscriptHash, hashLen);
                Expect(c_hs_t, "b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21");
            }

            // {server}  derive secret "tls13 s hs traffic":
            {
                string label = "s hs traffic";
                s_hs_t = TlsCryptoUtilities.HkdfExpandLabel(handshake, hash, label, serverHelloTranscriptHash, hashLen);
                Expect(s_hs_t, "b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38");
            }

            // {server}  derive secret for master "tls13 derived":
            {
                string label = "derived";
                master = TlsCryptoUtilities.HkdfExpandLabel(handshake, hash, label, emptyTranscriptHash, hashLen);
                Expect(master, "43 de 77 e0 c7 77 13 85 9a 94 4d b9 db 25 90 b5 31 90 a6 5b 3e e2 e4 f1 2d d7 a0 bb 7c e2 54 b4");
            }

            // {server}  extract secret "master":
            {
                TlsSecret ikm = m_crypto.HkdfInit(hash);
                master = master.HkdfExtract(hash, ikm);
                Expect(master, "18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a 47 80 01 bc 4d 4c 62 79 84 d5 a4 1d a8 d0 40 29 19");
            }

            // {server}  derive write traffic keys for handshake data:
            {
                TlsSecret key = TlsCryptoUtilities.HkdfExpandLabel(s_hs_t, hash, "key", TlsUtilities.EmptyBytes, 16);
                Expect(key, "3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e e4 03 bc");

                TlsSecret iv = TlsCryptoUtilities.HkdfExpandLabel(s_hs_t, hash, "iv", TlsUtilities.EmptyBytes, 12);
                Expect(iv, "5d 31 3e b2 67 12 76 ee 13 00 0b 30");
            }

            prfHash.Update(EncryptedExtensions, 0, EncryptedExtensions.Length);
            prfHash.Update(Certificate, 0, Certificate.Length);
            prfHash.Update(CertificateVerify, 0, CertificateVerify.Length);

            // {server}  calculate (server) finished "tls13 finished":
            {
                TlsSecret expanded = TlsCryptoUtilities.HkdfExpandLabel(s_hs_t, hash, "finished", TlsUtilities.EmptyBytes, hashLen);
                Expect(expanded, "00 8d 3b 66 f8 16 ea 55 9f 96 b5 37 e8 85 c3 1f c0 68 bf 49 2c 65 2f 01 f2 88 a1 d8 cd c1 9f c8");

                // TODO Mention this transcript hash in RFC 8448 data?
                byte[] transcriptHash = GetCurrentHash(prfHash);
                Expect(transcriptHash, "ed b7 72 5f a7 a3 47 3b 03 1e c8 ef 65 a2 48 54 93 90 01 38 a2 b9 12 91 40 7d 79 51 a0 61 10 ed");

                byte[] finished = expanded.CalculateHmac(hash, transcriptHash, 0, transcriptHash.Length);
                Expect(finished, Hex("9b 9b 14 1d 90 63 37 fb d2 cb dc e7 1d f4 de da 4a b4 2c 30 95 72 cb 7f ff ee 54 54 b7 8f 07 18"));
            }

            prfHash.Update(ServerFinished, 0, ServerFinished.Length);

            byte[] serverFinishedTranscriptHash = GetCurrentHash(prfHash);
            Expect(serverFinishedTranscriptHash, "96 08 10 2a 0f 1c cc 6d b6 25 0b 7b 7e 41 7b 1a 00 0e aa da 3d aa e4 77 7a 76 86 c9 ff 83 df 13");

            // {server}  derive secret "tls13 c ap traffic":
            {
                string label = "c ap traffic";
                c_ap_t = TlsCryptoUtilities.HkdfExpandLabel(master, hash, label, serverFinishedTranscriptHash, hashLen);
                Expect(c_ap_t, "9e 40 64 6c e7 9a 7f 9d c0 5a f8 88 9b ce 65 52 87 5a fa 0b 06 df 00 87 f7 92 eb b7 c1 75 04 a5");
            }

            // {server}  derive secret "tls13 s ap traffic":
            {
                string label = "s ap traffic";
                s_ap_t = TlsCryptoUtilities.HkdfExpandLabel(master, hash, label, serverFinishedTranscriptHash, hashLen);
                Expect(s_ap_t, "a1 1a f9 f0 55 31 f8 56 ad 47 11 6b 45 a9 50 32 82 04 b4 f4 4b fb 6b 3a 4b 4f 1f 3f cb 63 16 43");
            }

            // {server}  derive secret "tls13 exp master":
            {
                string label = "exp master";
                exp_master = TlsCryptoUtilities.HkdfExpandLabel(master, hash, label, serverFinishedTranscriptHash, hashLen);
                Expect(exp_master, "fe 22 f8 81 17 6e da 18 eb 8f 44 52 9e 67 92 c5 0c 9a 3f 89 45 2f 68 d8 ae 31 1b 43 09 d3 cf 50");
            }

            // {server}  derive write traffic keys for application data:
            {
                TlsSecret key = TlsCryptoUtilities.HkdfExpandLabel(s_ap_t, hash, "key", TlsUtilities.EmptyBytes, 16);
                Expect(key, "9f 02 28 3b 6c 9c 07 ef c2 6b b9 f2 ac 92 e3 56");

                TlsSecret iv = TlsCryptoUtilities.HkdfExpandLabel(s_ap_t, hash, "iv", TlsUtilities.EmptyBytes, 12);
                Expect(iv, "cf 78 2b 88 dd 83 54 9a ad f1 e9 84");
            }

            // {server}  derive read traffic keys for handshake data:
            {
                TlsSecret key = TlsCryptoUtilities.HkdfExpandLabel(c_hs_t, hash, "key", TlsUtilities.EmptyBytes, 16);
                Expect(key, "db fa a6 93 d1 76 2c 5b 66 6a f5 d9 50 25 8d 01");

                TlsSecret iv = TlsCryptoUtilities.HkdfExpandLabel(c_hs_t, hash, "iv", TlsUtilities.EmptyBytes, 12);
                Expect(iv, "5b d3 c7 1b 83 6e 0b 76 bb 73 26 5f");
            }

            // {server}  calculate (client) finished "tls13 finished":
            {
                TlsSecret expanded = TlsCryptoUtilities.HkdfExpandLabel(c_hs_t, hash, "finished", TlsUtilities.EmptyBytes, hashLen);
                Expect(expanded, "b8 0a d0 10 15 fb 2f 0b d6 5f f7 d4 da 5d 6b f8 3f 84 82 1d 1f 87 fd c7 d3 c7 5b 5a 7b 42 d9 c4");

                // TODO Mention this transcript hash in RFC 8448 data?
                byte[] finished = expanded.CalculateHmac(hash, serverFinishedTranscriptHash, 0, serverFinishedTranscriptHash.Length);
                Expect(finished, Hex("a8 ec 43 6d 67 76 34 ae 52 5a c1 fc eb e1 1a 03 9e c1 76 94 fa c6 e9 85 27 b6 42 f2 ed d5 ce 61"));
            }

            prfHash.Update(ClientFinished, 0, ClientFinished.Length);

            byte[] clientFinishedTranscriptHash = GetCurrentHash(prfHash);
            Expect(clientFinishedTranscriptHash, "20 91 45 a9 6e e8 e2 a1 22 ff 81 00 47 cc 95 26 84 65 8d 60 49 e8 64 29 42 6d b8 7c 54 ad 14 3d");

            // {server}  derive read traffic keys for application data:
            {
                TlsSecret key = TlsCryptoUtilities.HkdfExpandLabel(c_ap_t, hash, "key", TlsUtilities.EmptyBytes, 16);
                Expect(key, "17 42 2d da 59 6e d5 d9 ac d8 90 e3 c6 3f 50 51");

                TlsSecret iv = TlsCryptoUtilities.HkdfExpandLabel(c_ap_t, hash, "iv", TlsUtilities.EmptyBytes, 12);
                Expect(iv, "5b 78 92 3d ee 08 57 90 33 e5 23 d9");
            }

            // {server}  derive secret "tls13 res master":
            {
                res_master = TlsCryptoUtilities.HkdfExpandLabel(master, hash, "res master", clientFinishedTranscriptHash, hashLen);
                Expect(res_master, "7d f2 35 f2 03 1d 2a 05 12 87 d0 2b 02 41 b0 bf da f8 6c c8 56 23 1f 2d 5a ba 46 c4 34 ec 19 6c");
            }

            // {server}  generate resumption secret "tls13 resumption":
            {
                byte[] context = Hex("00 00");
                TlsSecret expanded = TlsCryptoUtilities.HkdfExpandLabel(res_master, hash, "resumption", context, hashLen);
                Expect(expanded, "4e cd 0e b6 ec 3b 4d 87 f5 d6 02 8f 92 2c a4 c5 85 1a 27 7f d4 13 11 c9 e6 2d 2c 94 92 e1 c4 f3");
            }
        }

        [Test]
        public void TestHkdfExpandLimit()
        {
            int[] hashes = new int[] { CryptoHashAlgorithm.md5, CryptoHashAlgorithm.sha1, CryptoHashAlgorithm.sha224,
                CryptoHashAlgorithm.sha256, CryptoHashAlgorithm.sha384, CryptoHashAlgorithm.sha512,
                CryptoHashAlgorithm.sm3 };

            for (int i = 0; i < hashes.Length; ++i)
            {
                int hash = hashes[i];
                if (!m_crypto.HasHkdfAlgorithm(hash))
                    continue;

                int hashLen = TlsCryptoUtilities.GetHashOutputSize(hash);
                TlsSecret zeros = m_crypto.HkdfInit(hash);

                int limit = 255 * hashLen;

                TlsSecret secret = m_crypto.HkdfInit(hash).HkdfExtract(hash, zeros);

                try
                {
                    secret.HkdfExpand(hash, TlsUtilities.EmptyBytes, limit);
                }
                catch (Exception e)
                {
                    Assert.Fail("Unexpected exception: " + e.Message);
                }

                try
                {
                    secret.HkdfExpand(hash, TlsUtilities.EmptyBytes, limit + 1);
                    Assert.Fail("Expected an exception!");
                }
                catch (ArgumentException)
                {
                    // Expected
                }
                catch (Exception e)
                {
                    Assert.Fail("Unexpected exception: " + e.Message);
                }
            }
        }

        [Test]
        public void TestSignaturesLegacy()
        {
            short[] signatureAlgorithms = new short[]{ SignatureAlgorithm.dsa, SignatureAlgorithm.ecdsa,
                SignatureAlgorithm.rsa };

            TlsCryptoParameters cryptoParams = new TestTlsCryptoParameters(ProtocolVersion.TLSv11);

            for (int i = 0; i < signatureAlgorithms.Length; ++i)
            {
                short signatureAlgorithm = signatureAlgorithms[i];
                if (!m_crypto.HasSignatureAlgorithm(signatureAlgorithm))
                    continue;

                TlsCredentialedSigner credentialedSigner = LoadCredentialedSignerLegacy(cryptoParams,
                    signatureAlgorithm);
                if (null != credentialedSigner)
                {
                    ImplTestSignatureLegacy(credentialedSigner);
                }
            }
        }

        [Test]
        public void TestSignatures12()
        {
            short[] hashAlgorithms = new short[]{ HashAlgorithm.md5, HashAlgorithm.sha1, HashAlgorithm.sha224,
                HashAlgorithm.sha256, HashAlgorithm.sha384, HashAlgorithm.sha512 };
            short[] signatureAlgorithms = new short[]{ SignatureAlgorithm.dsa, SignatureAlgorithm.ecdsa,
                SignatureAlgorithm.rsa };

            TlsCryptoParameters cryptoParams = new TestTlsCryptoParameters(ProtocolVersion.TLSv12);

            for (int i = 0; i < signatureAlgorithms.Length; ++i)
            {
                short signatureAlgorithm = signatureAlgorithms[i];

                for (int j = 0; j < hashAlgorithms.Length; ++j)
                {
                    SignatureAndHashAlgorithm signatureAndHashAlgorithm = SignatureAndHashAlgorithm.GetInstance(
                        hashAlgorithms[j], signatureAlgorithm);
                    if (!m_crypto.HasSignatureAndHashAlgorithm(signatureAndHashAlgorithm))
                        continue;

                    TlsCredentialedSigner credentialedSigner = LoadCredentialedSigner12(cryptoParams,
                        signatureAndHashAlgorithm);
                    if (null != credentialedSigner)
                    {
                        ImplTestSignature12(credentialedSigner, signatureAndHashAlgorithm);
                    }
                }
            }

            // Signature algorithms usable with HashAlgorithm.Intrinsic in TLS 1.2
            short[] intrinsicSignatureAlgorithms = new short[] { SignatureAlgorithm.ed25519, SignatureAlgorithm.ed448,
                SignatureAlgorithm.gostr34102012_256, SignatureAlgorithm.gostr34102012_512,
                SignatureAlgorithm.rsa_pss_pss_sha256, SignatureAlgorithm.rsa_pss_pss_sha384,
                SignatureAlgorithm.rsa_pss_pss_sha512, SignatureAlgorithm.rsa_pss_rsae_sha256,
                SignatureAlgorithm.rsa_pss_rsae_sha384, SignatureAlgorithm.rsa_pss_rsae_sha512, };

            for (int i = 0; i < intrinsicSignatureAlgorithms.Length; ++i)
            {
                SignatureAndHashAlgorithm signatureAndHashAlgorithm = SignatureAndHashAlgorithm.GetInstance(
                    HashAlgorithm.Intrinsic, intrinsicSignatureAlgorithms[i]);
                if (!m_crypto.HasSignatureAndHashAlgorithm(signatureAndHashAlgorithm))
                    continue;

                TlsCredentialedSigner credentialedSigner = LoadCredentialedSigner12(cryptoParams,
                    signatureAndHashAlgorithm);
                if (null != credentialedSigner)
                {
                    ImplTestSignature12(credentialedSigner, signatureAndHashAlgorithm);
                }
            }
        }

        [Test]
        public void TestSignatures13()
        {
            int[] signatureSchemes = new int[] { SignatureScheme.ecdsa_brainpoolP256r1tls13_sha256,
                SignatureScheme.ecdsa_brainpoolP384r1tls13_sha384, SignatureScheme.ecdsa_brainpoolP512r1tls13_sha512,
                SignatureScheme.ecdsa_secp256r1_sha256, SignatureScheme.ecdsa_secp384r1_sha384,
                SignatureScheme.ecdsa_secp521r1_sha512, SignatureScheme.ed25519, SignatureScheme.ed448,
                SignatureScheme.rsa_pss_pss_sha256, SignatureScheme.rsa_pss_pss_sha384, SignatureScheme.rsa_pss_pss_sha512,
                SignatureScheme.rsa_pss_rsae_sha256, SignatureScheme.rsa_pss_rsae_sha384,
                SignatureScheme.rsa_pss_rsae_sha512, SignatureScheme.sm2sig_sm3,
                // These are only used for certs in 1.3 (cert verification is not done by TlsCrypto)
                //SignatureScheme.ecdsa_sha1, SignatureScheme.rsa_pkcs1_sha1, SignatureScheme.rsa_pkcs1_sha256,
                //SignatureScheme.rsa_pkcs1_sha384, SignatureScheme.rsa_pkcs1_sha512,
            };

            TlsCryptoParameters cryptoParams = new TestTlsCryptoParameters(ProtocolVersion.TLSv13);

            for (int i = 0; i < signatureSchemes.Length; ++i)
            {
                int signatureScheme = signatureSchemes[i];
                if (!m_crypto.HasSignatureScheme(signatureScheme))
                    continue;

                TlsCredentialedSigner credentialedSigner = LoadCredentialedSigner13(cryptoParams, signatureScheme);
                if (null != credentialedSigner)
                {
                    ImplTestSignature13(credentialedSigner, signatureScheme);
                }
            }
        }

        private void Expect(TlsSecret secret, string expectedHex)
        {
            Expect(Extract(secret), Hex(expectedHex));
        }

        private void Expect(byte[] actualOctets, string expectedHex)
        {
            Expect(actualOctets, Hex(expectedHex));
        }

        private void Expect(byte[] actualOctets, byte[] expectedOctets)
        {
            AssertArrayEquals(actualOctets, expectedOctets);
        }

        private byte[] Extract(TlsSecret secret)
        {
            return m_crypto.AdoptSecret(secret).Extract();
        }

        private byte[] GetCurrentHash(TlsHash hash)
        {
            return hash.CloneHash().CalculateHash();
        }

        private static void AssertArrayEquals(byte[] a, byte[] b)
        {
            Assert.IsTrue(Arrays.AreEqual(a, b));
        }

        private static byte[] Hex(string s)
        {
            return Utilities.Encoders.Hex.Decode(s.Replace(" ", ""));
        }

        private byte[] ImplPrehash(int signatureScheme, byte[] message)
        {
            int cryptoHashAlgorithm = SignatureScheme.GetCryptoHashAlgorithm(signatureScheme);
            TlsHash tlsHash = m_crypto.CreateHash(cryptoHashAlgorithm);
            tlsHash.Update(message, 0, message.Length);
            return tlsHash.CalculateHash();
        }

        private byte[] ImplPrehash(SignatureAndHashAlgorithm signatureAndHashAlgorithm, byte[] message)
        {
            int signatureScheme = SignatureScheme.From(signatureAndHashAlgorithm);
            return ImplPrehash(signatureScheme, message);
        }

        private void ImplTestAgreement(TlsAgreement aA, TlsAgreement aB)
        {
            byte[] pA = aA.GenerateEphemeral();
            byte[] pB = aB.GenerateEphemeral();

            aA.ReceivePeerValue(pB);
            aB.ReceivePeerValue(pA);

            TlsSecret sA = aA.CalculateSecret();
            TlsSecret sB = aB.CalculateSecret();

            AssertArrayEquals(Extract(sA), Extract(sB));
        }

        private void ImplTestDHDomain(TlsDHConfig dhConfig)
        {
            int namedGroup = dhConfig.NamedGroup;
            int bits = namedGroup >= 0
                ? NamedGroup.GetFiniteFieldBits(namedGroup)
                : dhConfig.ExplicitGroup.P.BitLength;

            int rounds = System.Math.Max(2, 11 - (bits >> 10));

            TlsDHDomain d = m_crypto.CreateDHDomain(dhConfig);

            for (int i = 0; i < rounds; ++i)
            {
                TlsAgreement aA = d.CreateDH();
                TlsAgreement aB = d.CreateDH();

                ImplTestAgreement(aA, aB);
            }
        }

        private void ImplTestECDomain(TlsECConfig ecConfig)
        {
            int bits = NamedGroup.GetCurveBits(ecConfig.NamedGroup);
            int rounds = System.Math.Max(2, 12 - (bits >> 6));

            TlsECDomain d = m_crypto.CreateECDomain(ecConfig);

            for (int i = 0; i < rounds; ++i)
            {
                TlsAgreement aA = d.CreateECDH();
                TlsAgreement aB = d.CreateECDH();

                ImplTestAgreement(aA, aB);
            }
        }

        private void ImplTestSignatureLegacy(TlsCredentialedSigner credentialedSigner)
        {
            byte[] message = m_crypto.CreateNonceGenerator(TlsUtilities.EmptyBytes).GenerateNonce(100);

            byte[] signature;
            TlsStreamSigner tlsStreamSigner = credentialedSigner.GetStreamSigner();
            if (null != tlsStreamSigner)
            {
                Stream output = tlsStreamSigner.Stream;
                output.Write(message, 0, message.Length);
                signature = tlsStreamSigner.GetSignature();
            }
            else
            {
                TlsHash tlsHash = new CombinedHash(m_crypto);
                tlsHash.Update(message, 0, message.Length);
                byte[] hash = tlsHash.CalculateHash();
                signature = credentialedSigner.GenerateRawSignature(hash);
            }

            DigitallySigned digitallySigned = new DigitallySigned(null, signature);

            TlsCertificate tlsCertificate = credentialedSigner.Certificate.GetCertificateAt(0);
            TlsVerifier tlsVerifier = tlsCertificate.CreateVerifier(tlsCertificate.GetLegacySignatureAlgorithm());

            bool verified;
            TlsStreamVerifier tlsStreamVerifier = tlsVerifier.GetStreamVerifier(digitallySigned);
            if (null != tlsStreamVerifier)
            {
                Stream output = tlsStreamVerifier.Stream;
                output.Write(message, 0, message.Length);
                verified = tlsStreamVerifier.IsVerified();
            }
            else
            {
                TlsHash tlsHash = new CombinedHash(m_crypto);
                tlsHash.Update(message, 0, message.Length);
                byte[] hash = tlsHash.CalculateHash();
                verified = tlsVerifier.VerifyRawSignature(digitallySigned, hash);
            }

            Assert.IsTrue(verified);
        }

        private void ImplTestSignature12(TlsCredentialedSigner credentialedSigner,
            SignatureAndHashAlgorithm signatureAndHashAlgorithm)
        {
            byte[] message = m_crypto.CreateNonceGenerator(TlsUtilities.EmptyBytes).GenerateNonce(100);

            byte[] signature;
            TlsStreamSigner tlsStreamSigner = credentialedSigner.GetStreamSigner();
            if (null != tlsStreamSigner)
            {
                Stream output = tlsStreamSigner.Stream;
                output.Write(message, 0, message.Length);
                signature = tlsStreamSigner.GetSignature();
            }
            else
            {
                byte[] hash = ImplPrehash(signatureAndHashAlgorithm, message);
                signature = credentialedSigner.GenerateRawSignature(hash);
            }

            DigitallySigned digitallySigned = new DigitallySigned(signatureAndHashAlgorithm, signature);

            TlsCertificate tlsCertificate = credentialedSigner.Certificate.GetCertificateAt(0);
            TlsVerifier tlsVerifier = tlsCertificate.CreateVerifier(signatureAndHashAlgorithm.Signature);

            bool verified;
            TlsStreamVerifier tlsStreamVerifier = tlsVerifier.GetStreamVerifier(digitallySigned);
            if (null != tlsStreamVerifier)
            {
                Stream output = tlsStreamVerifier.Stream;
                output.Write(message, 0, message.Length);
                verified = tlsStreamVerifier.IsVerified();
            }
            else
            {
                byte[] hash = ImplPrehash(signatureAndHashAlgorithm, message);
                verified = tlsVerifier.VerifyRawSignature(digitallySigned, hash);
            }

            Assert.IsTrue(verified);
        }

        private void ImplTestSignature13(TlsCredentialedSigner credentialedSigner, int signatureScheme)
        {
            byte[] message = m_crypto.CreateNonceGenerator(TlsUtilities.EmptyBytes).GenerateNonce(100);

            byte[] signature;
            TlsStreamSigner tlsStreamSigner = credentialedSigner.GetStreamSigner();
            if (null != tlsStreamSigner)
            {
                Stream output = tlsStreamSigner.Stream;
                output.Write(message, 0, message.Length);
                signature = tlsStreamSigner.GetSignature();
            }
            else
            {
                byte[] hash = ImplPrehash(signatureScheme, message);
                signature = credentialedSigner.GenerateRawSignature(hash);
            }

            TlsCertificate tlsCertificate = credentialedSigner.Certificate.GetCertificateAt(0);
            Tls13Verifier tls13Verifier = tlsCertificate.CreateVerifier(signatureScheme);

            Stream output13 = tls13Verifier.Stream;
            output13.Write(message, 0, message.Length);
            bool verified = tls13Verifier.VerifySignature(signature);

            Assert.IsTrue(verified);
        }

        private class TestTlsCryptoParameters
            : TlsCryptoParameters
        {
            private readonly ProtocolVersion m_serverVersion;

            internal TestTlsCryptoParameters(ProtocolVersion serverVersion)
                : base(null)
            {
                this.m_serverVersion = serverVersion;
            }

            public override ProtocolVersion ServerVersion
            {
                get { return m_serverVersion; }
            }
        }

        private class TestTlsDHGroupVerifier
            : DefaultTlsDHGroupVerifier
        {
            internal IList<DHGroup> Groups
            {
                get { return m_groups; }
            }
        }
    }
}
