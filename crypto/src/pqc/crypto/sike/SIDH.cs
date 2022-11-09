namespace Org.BouncyCastle.Pqc.Crypto.Sike
{
internal sealed class Sidh
{
    private readonly SikeEngine engine;

    internal Sidh(SikeEngine engine)
    {
        this.engine = engine;
    }

    // Initialization of basis points
    internal void init_basis(ulong[] gen, ulong[][] XP, ulong[][] XQ, ulong[][] XR)
    {
       engine.fpx.fpcopy(gen, 0, XP[0]);
       engine.fpx.fpcopy(gen, engine.param.NWORDS_FIELD, XP[1]);
       engine.fpx.fpcopy(gen, 2 * engine.param.NWORDS_FIELD, XQ[0]);
       engine.fpx.fpcopy(gen, 3 * engine.param.NWORDS_FIELD, XQ[1]);
       engine.fpx.fpcopy(gen, 4 * engine.param.NWORDS_FIELD, XR[0]);
       engine.fpx.fpcopy(gen, 5 * engine.param.NWORDS_FIELD, XR[1]);
    }

    // Bob's ephemeral public key generation
    // Input:  a private key PrivateKeyB in the range [0, 2^Floor(Log(2,oB)) - 1].
    // Output: the public key PublicKeyB consisting of 3 elements in GF(p^2) which are encoded by removing leading 0 bytes.
    internal void EphemeralKeyGeneration_B(byte[] sk, byte[] pk)
    {
        PointProj R = new PointProj(engine.param.NWORDS_FIELD),
                phiP = new PointProj(engine.param.NWORDS_FIELD),
                phiQ = new PointProj(engine.param.NWORDS_FIELD),
                phiR = new PointProj(engine.param.NWORDS_FIELD);

        PointProj[] pts = new PointProj[engine.param.MAX_INT_POINTS_BOB];

        ulong[][] XPB = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            XQB = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            XRB = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            A24plus = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            A24minus = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            A = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD);

        ulong[][][] coeff = SikeUtilities.InitArray(3, 2, engine.param.NWORDS_FIELD);
        uint i, row, m, index = 0, npts = 0, ii = 0;
        uint[] pts_index = new uint[engine.param.MAX_INT_POINTS_BOB];
        ulong[] SecretKeyB = new ulong[engine.param.NWORDS_ORDER];

        // Initialize basis points
        init_basis(engine.param.B_gen, XPB, XQB, XRB);
        init_basis(engine.param.A_gen, phiP.X, phiQ.X, phiR.X);
        engine.fpx.fpcopy(engine.param.Montgomery_one,0,phiP.Z[0]);
        engine.fpx.fpcopy(engine.param.Montgomery_one,0,phiQ.Z[0]);
        engine.fpx.fpcopy(engine.param.Montgomery_one,0,phiR.Z[0]);

        // Initialize constants: A24minus = A-2C, A24plus = A+2C, where A=6, C=1
        engine.fpx.fpcopy(engine.param.Montgomery_one, 0,A24plus[0]);
        engine.fpx.mp2_add(A24plus, A24plus, A24plus);
        engine.fpx.mp2_add(A24plus, A24plus, A24minus);
        engine.fpx.mp2_add(A24plus, A24minus, A);
        engine.fpx.mp2_add(A24minus, A24minus, A24plus);
        engine.fpx.decode_to_digits(sk, engine.param.MSG_BYTES, SecretKeyB, engine.param.SECRETKEY_B_BYTES, engine.param.NWORDS_ORDER);
        engine.isogeny.LADDER3PT(XPB, XQB, XRB, SecretKeyB, engine.param.BOB, R, A);

        // Traverse tree
        index =0;
        for(row = 1; row < engine.param.MAX_Bob; row++)
        {
            while (index < engine.param.MAX_Bob - row)
            {
                pts[npts] = new PointProj(engine.param.NWORDS_FIELD);
                engine.fpx.fp2copy(R.X, pts[npts].X);
                engine.fpx.fp2copy(R.Z, pts[npts].Z);
                pts_index[npts++] = index;
                m = engine.param.strat_Bob[ii++];
                engine.isogeny.XTplE(R, R, A24minus, A24plus, m);
                index += m;
            }
            engine.isogeny.Get3Isog(R, A24minus, A24plus, coeff);

            for (i = 0; i < npts; i++)
            {
                engine.isogeny.Eval3Isog(pts[i], coeff);
            }
            engine.isogeny.Eval3Isog(phiP, coeff);
            engine.isogeny.Eval3Isog(phiQ, coeff);
            engine.isogeny.Eval3Isog(phiR, coeff);

            engine.fpx.fp2copy(pts[npts - 1].X, R.X);
            engine.fpx.fp2copy(pts[npts - 1].Z, R.Z);
            index = pts_index[npts - 1];
            npts -= 1;
        }
        engine.isogeny.Get3Isog(R, A24minus, A24plus, coeff);
        engine.isogeny.Eval3Isog(phiP, coeff);
        engine.isogeny.Eval3Isog(phiQ, coeff);
        engine.isogeny.Eval3Isog(phiR, coeff);
        engine.isogeny.Inv3Way(phiP.Z, phiQ.Z, phiR.Z);

        engine.fpx.fp2mul_mont(phiP.X, phiP.Z, phiP.X);
        engine.fpx.fp2mul_mont(phiQ.X, phiQ.Z, phiQ.X);
        engine.fpx.fp2mul_mont(phiR.X, phiR.Z, phiR.X);

        // Format public key
        engine.fpx.fp2_encode(phiP.X, pk, 0);
        engine.fpx.fp2_encode(phiQ.X, pk, engine.param.FP2_ENCODED_BYTES);
        engine.fpx.fp2_encode(phiR.X, pk, 2*engine.param.FP2_ENCODED_BYTES);
    }

    // Alice's ephemeral public key generation
    // Input:  a private key PrivateKeyA in the range [0, 2^eA - 1].
    // Output: the public key PublicKeyA consisting of 3 elements in GF(p^2) which are encoded by removing leading 0 bytes.
    internal void EphemeralKeyGeneration_A(byte[] ephemeralsk, byte[] ct)
    {
        PointProj R = new PointProj(engine.param.NWORDS_FIELD),
                phiP = new PointProj(engine.param.NWORDS_FIELD),
                phiQ = new PointProj(engine.param.NWORDS_FIELD),
                phiR = new PointProj(engine.param.NWORDS_FIELD);

        PointProj[] pts = new PointProj[engine.param.MAX_INT_POINTS_ALICE];
        ulong[][] XPA = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            XQA = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            XRA = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            A24plus = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            C24 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            A = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD);

        ulong[][][] coeff = SikeUtilities.InitArray(3, 2, engine.param.NWORDS_FIELD);
        uint index = 0, npts = 0, ii = 0, m, i, row;
        uint[] pts_index = new uint[engine.param.MAX_INT_POINTS_ALICE];
        ulong[] SecretKeyA = new ulong[engine.param.NWORDS_ORDER];

        // Initialize basis points
        init_basis(engine.param.A_gen, XPA, XQA, XRA);
        init_basis(engine.param.B_gen, phiP.X, phiQ.X, phiR.X);
        engine.fpx.fpcopy(engine.param.Montgomery_one, 0, phiP.Z[0]);
        engine.fpx.fpcopy(engine.param.Montgomery_one, 0, phiQ.Z[0]);
        engine.fpx.fpcopy(engine.param.Montgomery_one, 0, phiR.Z[0]);

        // Initialize constants: A24plus = A+2C, C24 = 4C, where A=6, C=1
        engine.fpx.fpcopy(engine.param.Montgomery_one, 0, A24plus[0]);
        engine.fpx.mp2_add(A24plus, A24plus, A24plus);
        engine.fpx.mp2_add(A24plus, A24plus, C24);
        engine.fpx.mp2_add(A24plus, C24, A);
        engine.fpx.mp2_add(C24, C24, A24plus);

        // Retrieve kernel point
        engine.fpx.decode_to_digits(ephemeralsk, 0, SecretKeyA, engine.param.SECRETKEY_A_BYTES, engine.param.NWORDS_ORDER);
        engine.isogeny.LADDER3PT(XPA, XQA, XRA, SecretKeyA, engine.param.ALICE, R, A);

        if (engine.param.OALICE_BITS % 2 == 1)
        {
            PointProj S = new PointProj(engine.param.NWORDS_FIELD);
            engine.isogeny.XDblE(R, S, A24plus, C24, (engine.param.OALICE_BITS - 1));
            engine.isogeny.Get2Isog(S, A24plus, C24);
            engine.isogeny.Eval2Isog(phiP, S);
            engine.isogeny.Eval2Isog(phiQ, S);
            engine.isogeny.Eval2Isog(phiR, S);
            engine.isogeny.Eval2Isog(R, S);
        }

        // Traverse tree
        index = 0;
        for (row = 1; row < engine.param.MAX_Alice; row++)
        {
            while (index < engine.param.MAX_Alice-row)
            {
                pts[npts] = new PointProj(engine.param.NWORDS_FIELD);
                engine.fpx.fp2copy(R.X, pts[npts].X);
                engine.fpx.fp2copy(R.Z, pts[npts].Z);
                pts_index[npts++] = index;
                m = engine.param.strat_Alice[ii++];
                engine.isogeny.XDblE(R, R, A24plus, C24, 2*m);
                index += m;
            }
            engine.isogeny.Get4Isog(R, A24plus, C24, coeff);

            for (i = 0; i < npts; i++)
            {
                engine.isogeny.Eval4Isog(pts[i], coeff);
            }
            engine.isogeny.Eval4Isog(phiP, coeff);
            engine.isogeny.Eval4Isog(phiQ, coeff);
            engine.isogeny.Eval4Isog(phiR, coeff);

            engine.fpx.fp2copy(pts[npts-1].X, R.X);
            engine.fpx.fp2copy(pts[npts-1].Z, R.Z);
            index = pts_index[npts-1];
            npts -= 1;
        }

        engine.isogeny.Get4Isog(R, A24plus, C24, coeff);
        engine.isogeny.Eval4Isog(phiP, coeff);
        engine.isogeny.Eval4Isog(phiQ, coeff);
        engine.isogeny.Eval4Isog(phiR, coeff);

        engine.isogeny.Inv3Way(phiP.Z, phiQ.Z, phiR.Z);
        engine.fpx.fp2mul_mont(phiP.X, phiP.Z, phiP.X);
        engine.fpx.fp2mul_mont(phiQ.X, phiQ.Z, phiQ.X);
        engine.fpx.fp2mul_mont(phiR.X, phiR.Z, phiR.X);

        // Format public key
        engine.fpx.fp2_encode(phiP.X, ct,0);
        engine.fpx.fp2_encode(phiQ.X, ct, engine.param.FP2_ENCODED_BYTES);
        engine.fpx.fp2_encode(phiR.X, ct,2*engine.param.FP2_ENCODED_BYTES);

    }

    // Alice's ephemeral shared secret computation
    // It produces a shared secret key SharedSecretA using her secret key PrivateKeyA and Bob's public key PublicKeyB
    // Inputs: Alice's PrivateKeyA is an integer in the range [0, oA-1].
    //         Bob's PublicKeyB consists of 3 elements in GF(p^2) encoded by removing leading 0 bytes.
    // Output: a shared secret SharedSecretA that consists of one element in GF(p^2) encoded by removing leading 0 bytes.
    internal void EphemeralSecretAgreement_A(byte[] ephemeralsk, byte[] pk, byte[] jinvariant)
    {
        PointProj R = new PointProj(engine.param.NWORDS_FIELD);
        PointProj[] pts = new PointProj[engine.param.MAX_INT_POINTS_ALICE];
        ulong[][][] PKB = SikeUtilities.InitArray(3, 2, engine.param.NWORDS_FIELD),
            coeff = SikeUtilities.InitArray(3, 2, engine.param.NWORDS_FIELD);
        ulong[][] jinv = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            A24plus = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            C24 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            A = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD);

        uint i = 0, row = 0, m = 0, index = 0, npts = 0, ii = 0;
        uint[] pts_index = new uint[engine.param.MAX_INT_POINTS_ALICE];
        ulong[] SecretKeyA = new ulong[engine.param.NWORDS_ORDER];

        // Initialize images of Bob's basis
        engine.fpx.fp2_decode(pk, PKB[0], 0);
        engine.fpx.fp2_decode(pk, PKB[1], engine.param.FP2_ENCODED_BYTES);
        engine.fpx.fp2_decode(pk, PKB[2], 2*engine.param.FP2_ENCODED_BYTES);

        // Initialize constants: A24plus = A+2C, C24 = 4C, where C=1
        engine.isogeny.GetA(PKB[0], PKB[1], PKB[2], A);
        engine.fpx.mp_add(engine.param.Montgomery_one, engine.param.Montgomery_one, C24[0], engine.param.NWORDS_FIELD);
        engine.fpx.mp2_add(A, C24, A24plus);
        engine.fpx.mp_add(C24[0], C24[0], C24[0], engine.param.NWORDS_FIELD);

        // Retrieve kernel point
        engine.fpx.decode_to_digits(ephemeralsk, 0, SecretKeyA, engine.param.SECRETKEY_A_BYTES, engine.param.NWORDS_ORDER);
        engine.isogeny.LADDER3PT(PKB[0], PKB[1], PKB[2], SecretKeyA, engine.param.ALICE, R, A);

        if (engine.param.OALICE_BITS % 2 == 1)
        {
            PointProj S = new PointProj(engine.param.NWORDS_FIELD);

            engine.isogeny.XDblE(R, S, A24plus, C24, engine.param.OALICE_BITS - 1);
            engine.isogeny.Get2Isog(S, A24plus, C24);
            engine.isogeny.Eval2Isog(R, S);
        }

        // Traverse tree
        index = 0;
        for (row = 1; row < engine.param.MAX_Alice; row++)
        {
            while (index < engine.param.MAX_Alice-row)
            {
                pts[npts] = new PointProj(engine.param.NWORDS_FIELD);
                engine.fpx.fp2copy(R.X, pts[npts].X);
                engine.fpx.fp2copy(R.Z, pts[npts].Z);
                pts_index[npts++] = index;
                m = engine.param.strat_Alice[ii++];
                engine.isogeny.XDblE(R, R, A24plus, C24, 2*m);
                index += m;
            }
            engine.isogeny.Get4Isog(R, A24plus, C24, coeff);

            for (i = 0; i < npts; i++)
            {
                engine.isogeny.Eval4Isog(pts[i], coeff);
            }

            engine.fpx.fp2copy(pts[npts-1].X, R.X);
            engine.fpx.fp2copy(pts[npts-1].Z, R.Z);
            index = pts_index[npts-1];
            npts -= 1;
        }

        engine.isogeny.Get4Isog(R, A24plus, C24, coeff);
        engine.fpx.mp2_add(A24plus, A24plus, A24plus);
        engine.fpx.fp2sub(A24plus, C24, A24plus);
        engine.fpx.fp2add(A24plus, A24plus, A24plus);
        engine.isogeny.JInv(A24plus, C24, jinv);
        engine.fpx.fp2_encode(jinv, jinvariant, 0);    // Format shared secret
    }

    // Bob's ephemeral shared secret computation
    // It produces a shared secret key SharedSecretB using his secret key PrivateKeyB and Alice's public key PublicKeyA
    // Inputs: Bob's PrivateKeyB is an integer in the range [0, 2^Floor(Log(2,oB)) - 1].
    //         Alice's PublicKeyA consists of 3 elements in GF(p^2) encoded by removing leading 0 bytes.
    // Output: a shared secret SharedSecretB that consists of one element in GF(p^2) encoded by removing leading 0 bytes.
    internal void EphemeralSecretAgreement_B(byte[] sk, byte[] ct, byte[] jinvariant_)
    {
        PointProj R = new PointProj(engine.param.NWORDS_FIELD);
        PointProj[] pts = new PointProj[engine.param.MAX_INT_POINTS_BOB];
        ulong[][][] coeff = SikeUtilities.InitArray(3, 2, engine.param.NWORDS_FIELD),
            PKB = SikeUtilities.InitArray(3, 2, engine.param.NWORDS_FIELD);

        ulong[][] jinv = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            A24plus = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            A24minus = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            A = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD);
        uint i, row, m, index = 0, npts = 0, ii = 0;
        uint[] pts_index = new uint[engine.param.MAX_INT_POINTS_BOB];
        ulong[] SecretKeyB = new ulong[engine.param.NWORDS_ORDER];

        // Initialize images of Alice's basis
        engine.fpx.fp2_decode(ct,  PKB[0], 0);
        engine.fpx.fp2_decode(ct, PKB[1], engine.param.FP2_ENCODED_BYTES);
        engine.fpx.fp2_decode(ct, PKB[2], 2*engine.param.FP2_ENCODED_BYTES);

        // Initialize constants: A24plus = A+2C, A24minus = A-2C, where C=1
        engine.isogeny.GetA(PKB[0], PKB[1], PKB[2], A);
        engine.fpx.mp_add(engine.param.Montgomery_one, engine.param.Montgomery_one, A24minus[0], engine.param.NWORDS_FIELD);
        engine.fpx.mp2_add(A, A24minus, A24plus);
        engine.fpx.mp2_sub_p2(A, A24minus, A24minus);

        // Retrieve kernel point
        engine.fpx.decode_to_digits(sk, engine.param.MSG_BYTES, SecretKeyB, engine.param.SECRETKEY_B_BYTES, engine.param.NWORDS_ORDER);
        engine.isogeny.LADDER3PT(PKB[0], PKB[1], PKB[2], SecretKeyB, engine.param.BOB, R, A);

        // Traverse tree
        index = 0;
        for (row = 1; row < engine.param.MAX_Bob; row++)
        {
            while (index < engine.param.MAX_Bob-row)
            {
                pts[npts] = new PointProj(engine.param.NWORDS_FIELD);
                engine.fpx.fp2copy(R.X, pts[npts].X);
                engine.fpx.fp2copy(R.Z, pts[npts].Z);
                pts_index[npts++] = index;
                m = engine.param.strat_Bob[ii++];
                engine.isogeny.XTplE(R, R, A24minus, A24plus, m);
                index += m;
            }
            engine.isogeny.Get3Isog(R, A24minus, A24plus, coeff);

            for (i = 0; i < npts; i++) {
                engine.isogeny.Eval3Isog(pts[i], coeff);
            }

            engine.fpx.fp2copy(pts[npts-1].X, R.X);
            engine.fpx.fp2copy(pts[npts-1].Z, R.Z);
            index = pts_index[npts-1];
            npts -= 1;
        }

        engine.isogeny.Get3Isog(R, A24minus, A24plus, coeff);
        engine.fpx.fp2add(A24plus, A24minus, A);
        engine.fpx.fp2add(A, A, A);
        engine.fpx.fp2sub(A24plus, A24minus, A24plus);
        engine.isogeny.JInv(A, A24plus, jinv);
        engine.fpx.fp2_encode(jinv, jinvariant_, 0);    // Format shared secret
    }
}
}
