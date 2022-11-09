namespace Org.BouncyCastle.Pqc.Crypto.Sike
{
internal sealed class Isogeny
{
    private readonly SikeEngine engine;

    internal Isogeny(SikeEngine engine)
    {
        this.engine = engine;
    }

    // Doubling of a Montgomery point in projective coordinates (X:Z) over affine curve coefficient A. 
    // Input: projective Montgomery x-coordinates P = (X1:Z1), where x1=X1/Z1 and Montgomery curve constants (A+2)/4.
    // Output: projective Montgomery x-coordinates Q = 2*P = (X2:Z2). 
    internal void Double(PointProj P, PointProj Q, ulong[][] A24, uint k)
    {
        ulong[][] temp = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            a = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            b = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            c = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            aa = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            bb = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD);
        engine.fpx.fp2copy(P.X, Q.X);
        engine.fpx.fp2copy(P.Z, Q.Z);

        for (int j = 0; j < k; j++)
        {
            engine.fpx.fp2add(Q.X, Q.Z, a);
            engine.fpx.fp2sub(Q.X, Q.Z, b);
            engine.fpx.fp2sqr_mont(a, aa);
            engine.fpx.fp2sqr_mont(b, bb);
            engine.fpx.fp2sub(aa, bb, c);
            engine.fpx.fp2mul_mont(aa, bb, Q.X);
            engine.fpx.fp2mul_mont(A24, c, temp);
            engine.fpx.fp2add(temp, bb, temp);
            engine.fpx.fp2mul_mont(c, temp, Q.Z);
        }
    }

    internal void CompleteMPoint(ulong[][] A, PointProj P, PointProjFull R)
    { // Given an xz-only representation on a montgomery curve, compute its affine representation
        ulong[][] zero = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            one = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            xz = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            yz = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            s2 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            r2 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            invz = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            temp0 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            temp1 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD);


            engine.fpx.fpcopy(engine.param.Montgomery_one,0, one[0]);
        
        if (!Fpx.subarrayEquals(P.Z[0], zero[0], engine.param.NWORDS_FIELD) || !Fpx.subarrayEquals(P.Z[1], zero[1], engine.param.NWORDS_FIELD))
        {
            engine.fpx.fp2mul_mont(P.X, P.Z, xz);       // xz = x*z;
            engine.fpx.fpsubPRIME(P.X[0], P.Z[1], temp0[0]);
            engine.fpx.fpaddPRIME(P.X[1], P.Z[0], temp0[1]);
            engine.fpx.fpaddPRIME(P.X[0], P.Z[1], temp1[0]);
            engine.fpx.fpsubPRIME(P.X[1], P.Z[0], temp1[1]);
            engine.fpx.fp2mul_mont(temp0, temp1, s2);     // s2 = (x + i*z)*(x - i*z);
            engine.fpx.fp2mul_mont(A, xz, temp0);
            engine.fpx.fp2add(temp0, s2, temp1);
            engine.fpx.fp2mul_mont(xz, temp1, r2);        // r2 = xz*(A*xz + s2);
            engine.fpx.sqrt_Fp2(r2, yz);
            engine.fpx.fp2copy(P.Z, invz);
            engine.fpx.fp2inv_mont_bingcd(invz);
            engine.fpx.fp2mul_mont(P.X, invz, R.X);
            engine.fpx.fp2sqr_mont(invz, temp0);
            engine.fpx.fp2mul_mont(yz, temp0, R.Y);      // R = EM![x*invz, yz*invz^2];
            engine.fpx.fp2copy(one, R.Z);
        }
        else
        {
            engine.fpx.fp2copy(zero, R.X);
            engine.fpx.fp2copy(one, R.Y);
            engine.fpx.fp2copy(zero, R.Z);               // R = EM!0;
        }
    }

    internal void Ladder(PointProj P, ulong[] m, ulong[][] A, uint order_bits, PointProj R)
    {
        var R0 = new PointProj(engine.param.NWORDS_FIELD);
        var R1 = new PointProj(engine.param.NWORDS_FIELD);
        ulong[][] A24 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD);
        ulong mask;
        int j, swap, prevbit = 0;
        
        
        engine.fpx.fpcopy(engine.param.Montgomery_one, 0, A24[0]);
        engine.fpx.fpaddPRIME(A24[0], A24[0], A24[0]);
        engine.fpx.fp2add(A, A24, A24);
        engine.fpx.fp2div2(A24, A24);
        engine.fpx.fp2div2(A24, A24);  // A24 = (A+2)/4          

        j = (int)order_bits - 1;
        uint bit = (uint) ((m[j >> (int)Internal.LOG2RADIX] >> (int)(j & (Internal.RADIX-1))) & 1);
        while (bit == 0)
        {
            j--;
            bit = (uint) ((m[j >> (int)Internal.LOG2RADIX] >> (int)(j & (Internal.RADIX-1))) & 1);
        }

        // R0 <- P, R1 <- 2P
        engine.fpx.fp2copy(P.X, R0.X);
        engine.fpx.fp2copy(P.Z, R0.Z);
        XDblE(P, R1, A24, 1);

        // Main loop
        for (int i = (int)j - 1;  i >= 0; i--) 
        {
            bit = (uint)((m[i >> (int)Internal.LOG2RADIX] >> (int)(i & (Internal.RADIX-1))) & 1);
            swap = (int) (bit ^ prevbit);
            prevbit = (int) bit;
            mask = (ulong) (0 - swap);

            SwapPoints(R0, R1, mask);
            XDblAddProj(R0, R1, P.X, P.Z, A24);
        }
        swap = 0 ^ prevbit;
        mask = (ulong) (0 - swap);
        SwapPoints(R0, R1, mask);

        engine.fpx.fp2copy(R0.X, R.X);
        engine.fpx.fp2copy(R0.Z, R.Z);
    }

    // Simultaneous doubling and differential addition.
    // Input: projective Montgomery points P=(XP:ZP) and Q=(XQ:ZQ) such that xP=XP/ZP and xQ=XQ/ZQ, affine difference xPQ=x(P-Q) and Montgomery curve constant A24=(A+2)/4.
    // Output: projective Montgomery points P <- 2*P = (X2P:Z2P) such that x(2P)=X2P/Z2P, and Q <- P+Q = (XQP:ZQP) such that = x(Q+P)=XQP/ZQP.
    private void XDblAddProj(PointProj P, PointProj Q, ulong[][] XPQ, ulong[][] ZPQ, ulong[][] A24)
    {
        ulong[][] t0 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            t1 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            t2 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD);


        engine.fpx.fp2add(P.X, P.Z, t0);                         // t0 = XP+ZP
        engine.fpx.fp2sub(P.X, P.Z, t1);                         // t1 = XP-ZP
        engine.fpx.fp2sqr_mont(t0, P.X);                          // XP = (XP+ZP)^2
        engine.fpx.fp2sub(Q.X, Q.Z, t2);                         // t2 = XQ-ZQ
        engine.fpx.fp2correction(t2);
        engine.fpx.fp2add(Q.X, Q.Z, Q.X);                       // XQ = XQ+ZQ
        engine.fpx.fp2mul_mont(t0, t2, t0);                        // t0 = (XP+ZP)*(XQ-ZQ)
        engine.fpx.fp2sqr_mont(t1, P.Z);                          // ZP = (XP-ZP)^2
        engine.fpx.fp2mul_mont(t1, Q.X, t1);                      // t1 = (XP-ZP)*(XQ+ZQ)
        engine.fpx.fp2sub(P.X, P.Z, t2);                         // t2 = (XP+ZP)^2-(XP-ZP)^2
        engine.fpx.fp2mul_mont(P.X, P.Z, P.X);                  // XP = (XP+ZP)^2*(XP-ZP)^2
        engine.fpx.fp2mul_mont(t2, A24, Q.X);                     // XQ = A24*[(XP+ZP)^2-(XP-ZP)^2]
        engine.fpx.fp2sub(t0, t1, Q.Z);                           // ZQ = (XP+ZP)*(XQ-ZQ)-(XP-ZP)*(XQ+ZQ)
        engine.fpx.fp2add(Q.X, P.Z, P.Z);                       // ZP = A24*[(XP+ZP)^2-(XP-ZP)^2]+(XP-ZP)^2
        engine.fpx.fp2add(t0, t1, Q.X);                           // XQ = (XP+ZP)*(XQ-ZQ)+(XP-ZP)*(XQ+ZQ)
        engine.fpx.fp2mul_mont(P.Z, t2, P.Z);                    // ZP = [A24*[(XP+ZP)^2-(XP-ZP)^2]+(XP-ZP)^2]*[(XP+ZP)^2-(XP-ZP)^2]
        engine.fpx.fp2sqr_mont(Q.Z, Q.Z);                        // ZQ = [(XP+ZP)*(XQ-ZQ)-(XP-ZP)*(XQ+ZQ)]^2
        engine.fpx.fp2sqr_mont(Q.X, Q.X);                        // XQ = [(XP+ZP)*(XQ-ZQ)+(XP-ZP)*(XQ+ZQ)]^2
        engine.fpx.fp2mul_mont(Q.X, ZPQ, Q.X);                   // XQ = ZPQ*[(XP+ZP)*(XQ-ZQ)+(XP-ZP)*(XQ+ZQ)]^2
        engine.fpx.fp2mul_mont(Q.Z, XPQ, Q.Z);                   // ZQ = XPQ*[(XP+ZP)*(XQ-ZQ)-(XP-ZP)*(XQ+ZQ)]^2
    }

    // Doubling of a Montgomery point in projective coordinates (X:Z) over affine curve coefficient A.
    // Input: projective Montgomery x-coordinates P = (X1:Z1), where x1=X1/Z1 and Montgomery curve constants (A+2)/4.
    // Output: projective Montgomery x-coordinates Q = 2*P = (X2:Z2).
    private void XDblE(PointProj P, PointProj Q, ulong[][] A24, int e)
    {
        ulong[][] temp = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            a = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            b = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            c = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            aa = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            bb = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD);


        engine.fpx.fp2copy(P.X,Q.X);
        engine.fpx.fp2copy(P.Z,Q.Z);

        for (int j = 0; j < e; j++)
        {
            engine.fpx.fp2add(Q.X, Q.Z, a);           // a = xQ + zQ
            engine.fpx.fp2sub(Q.X, Q.Z, b);           // b = xQ - zQ
            engine.fpx.fp2sqr_mont(a, aa);              //aa = (xQ + zQ)^2
            engine.fpx.fp2sqr_mont(b, bb);              //bb = (xQ - zQ)^2
            engine.fpx.fp2sub(aa, bb, c);               // c = (xQ + zQ)^2 - (xQ - zQ)^2
            engine.fpx.fp2mul_mont(aa, bb, Q.X);       // xQ = (xQ + zQ)^2 * (xQ - zQ)^2
            engine.fpx.fp2mul_mont(A24, c, temp);       // temp = A24 * ((xQ + zQ)^2 - (xQ - zQ)^2)
            engine.fpx.fp2add(temp, bb, temp);          // temp = A24 * ((xQ + zQ)^2 - (xQ - zQ)^2) + (xQ - zQ)^2
            engine.fpx.fp2mul_mont(c, temp, Q.Z);      // temp =  (A24 * ((xQ + zQ)^2 - (xQ - zQ)^2) + (xQ - zQ)^2) * ((xQ + zQ)^2 - (xQ - zQ)^2)
        }
    }

    // Computes [3^e](X:Z) on Montgomery curve with projective constant via e repeated triplings. e triplings in E costs k*(5M + 6S + 9A)
    // Input: projective Montgomery x-coordinates P = (X:Z), where x=X/Z, Montgomery curve constant A2 = A/2 and the number of triplings e.
    // Output: projective Montgomery x-coordinates Q <- [3^e]P.
    internal void XTplEFast(PointProj P, PointProj Q, ulong[][] A2, uint e)
    {
        var T = new PointProj(engine.param.NWORDS_FIELD);

        engine.fpx.copy_words(P, T);
        for (int j = 0; j < e; j++)
        {
            XTplFast(T, T, A2);
        }
        engine.fpx.copy_words(T, Q);
    }

    // Montgomery curve (E: y^2 = x^3 + A*x^2 + x) x-only tripling at a cost 5M + 6S + 9A = 27p + 61a.
    // Input : projective Montgomery x-coordinates P = (X:Z), where x=X/Z and Montgomery curve constant A/2.
    // Output: projective Montgomery x-coordinates Q = 3*P = (X3:Z3).
    private void XTplFast(PointProj P, PointProj Q, ulong[][] A2)
    {
        ulong[][] t1 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            t2 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            t3 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            t4 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD);


        engine.fpx.fp2sqr_mont(P.X, t1);        // t1 = x^2
        engine.fpx.fp2sqr_mont(P.Z, t2);        // t2 = z^2
        engine.fpx.fp2add(t1, t2, t3);          // t3 = t1 + t2
        engine.fpx.fp2add(P.X, P.Z, t4);        // t4 = x + z
        engine.fpx.fp2sqr_mont(t4, t4);         // t4 = t4^2
        engine.fpx.fp2sub(t4, t3, t4);          // t4 = t4 - t3
        engine.fpx.fp2mul_mont(A2, t4, t4);     // t4 = t4*A2
        engine.fpx.fp2add(t3, t4, t4);          // t4 = t4 + t3
        engine.fpx.fp2sub(t1, t2, t3);          // t3 = t1 - t2
        engine.fpx.fp2sqr_mont(t3, t3);         // t3 = t3^2
        engine.fpx.fp2mul_mont(t1, t4, t1);     // t1 = t1*t4
        engine.fpx.fp2shl(t1, 2, t1);        // t1 = 4*t1
        engine.fpx.fp2sub(t1, t3, t1);          // t1 = t1 - t3
        engine.fpx.fp2sqr_mont(t1, t1);         // t1 = t1^2
        engine.fpx.fp2mul_mont(t2, t4, t2);     // t2 = t2*t4
        engine.fpx.fp2shl(t2, 2, t2);        // t2 = 4*t2
        engine.fpx.fp2sub(t2, t3, t2);          // t2 = t2 - t3
        engine.fpx.fp2sqr_mont(t2, t2);         // t2 = t2^2
        engine.fpx.fp2mul_mont(P.X, t2, Q.X);   // x = x*t2
        engine.fpx.fp2mul_mont(P.Z, t1, Q.Z);   // z = z*t1
    }


    internal void LADDER3PT(ulong[][] xP, ulong[][] xQ, ulong[][] xPQ, ulong[] m, uint AliceOrBob, PointProj R, ulong[][] A)
    {
        var R0 = new PointProj(engine.param.NWORDS_FIELD);
        var R2 = new PointProj(engine.param.NWORDS_FIELD);
        ulong[][] A24 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD);
        ulong mask;
        uint i, nbits, bit, swap, prevbit = 0;

        if (AliceOrBob == engine.param.ALICE)
        {
            nbits = engine.param.OALICE_BITS;
        } else
        {
            nbits = engine.param.OBOB_BITS - 1;
        }

        // Initializing constant
        engine.fpx.fpcopy(engine.param.Montgomery_one, 0, A24[0]);
        engine.fpx.mp2_add(A24, A24, A24);
        engine.fpx.mp2_add(A, A24, A24);
        engine.fpx.fp2div2(A24, A24);
        engine.fpx.fp2div2(A24, A24);  // A24 = (A+2)/4

        // Initializing points
        engine.fpx.fp2copy(xQ, R0.X);
        engine.fpx.fpcopy(engine.param.Montgomery_one, 0, R0.Z[0]);
        engine.fpx.fp2copy(xPQ, R2.X);
        engine.fpx.fpcopy(engine.param.Montgomery_one, 0, R2.Z[0]);
        engine.fpx.fp2copy(xP, R.X);
        engine.fpx.fpcopy(engine.param.Montgomery_one, 0, R.Z[0]);
        engine.fpx.fpzero((R.Z)[1]);

        // Main loop
        for (i = 0; i < nbits; i++)
        {
            bit = (uint) ((m[i >> (int)Internal.LOG2RADIX] >> (int)(i & (Internal.RADIX-1))) & 1);
            swap = bit ^ prevbit;
            prevbit = bit;
            mask = 0 - (ulong) swap;
            SwapPoints(R, R2, mask);
            XDblAdd(R0, R2, R.X, A24);
            engine.fpx.fp2mul_mont(R2.X, R.Z, R2.X);
        }
        swap = 0 ^ prevbit;
        mask = 0 - (ulong)swap;
        SwapPoints(R, R2, mask);
    }

    // Complete point on A = 0 curve
    internal void CompletePoint(PointProj P, PointProjFull R)
    {
        ulong[][] xz = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            s2 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            r2 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            yz = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            invz = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            t0 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            t1 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            one = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD);

        engine.fpx.fpcopy(engine.param.Montgomery_one, 0, one[0]);
        engine.fpx.fp2mul_mont(P.X, P.Z, xz);
        engine.fpx.fpsubPRIME(P.X[0], P.Z[1], t0[0]);
        engine.fpx.fpaddPRIME(P.X[1], P.Z[0], t0[1]);
        engine.fpx.fpaddPRIME(P.X[0], P.Z[1], t1[0]);
        engine.fpx.fpsubPRIME(P.X[1], P.Z[0], t1[1]);
        engine.fpx.fp2mul_mont(t0, t1, s2);
        engine.fpx.fp2mul_mont(xz, s2, r2);
        engine.fpx.sqrt_Fp2(r2, yz);//todo check
        engine.fpx.fp2copy(P.Z,invz);
        engine.fpx.fp2inv_mont_bingcd(invz);
        engine.fpx.fp2mul_mont(P.X, invz, R.X);
        engine.fpx.fp2sqr_mont(invz, t0);
        engine.fpx.fp2mul_mont(yz, t0, R.Y);
        engine.fpx.fp2copy(one, R.Z);
    }


    // Swap points.
    // If option = 0 then P <- P and Q <- Q, else if option = 0xFF...FF then P <- Q and Q <- P
    internal void SwapPoints(PointProj P, PointProj Q, ulong option)
    {
        //todo/org : put this in the PointProj class
        ulong temp;
        for (int i = 0; i < engine.param.NWORDS_FIELD; i++)
        {
            temp = option & (P.X[0][i] ^ Q.X[0][i]);
            P.X[0][i] = temp ^ P.X[0][i];
            Q.X[0][i] = temp ^ Q.X[0][i];
            temp = option & (P.X[1][i] ^ Q.X[1][i]);
            P.X[1][i] = temp ^ P.X[1][i];
            Q.X[1][i] = temp ^ Q.X[1][i];
            temp = option & (P.Z[0][i] ^ Q.Z[0][i]);
            P.Z[0][i] = temp ^ P.Z[0][i];
            Q.Z[0][i] = temp ^ Q.Z[0][i];
            temp = option & (P.Z[1][i] ^ Q.Z[1][i]);
            P.Z[1][i] = temp ^ P.Z[1][i];
            Q.Z[1][i] = temp ^ Q.Z[1][i];
        }
    }

    // Simultaneous doubling and differential addition.
    // Input: projective Montgomery points P=(XP:ZP) and Q=(XQ:ZQ) such that xP=XP/ZP and xQ=XQ/ZQ, affine difference xPQ=x(P-Q) and Montgomery curve constant A24=(A+2)/4.
    // Output: projective Montgomery points P <- 2*P = (X2P:Z2P) such that x(2P)=X2P/Z2P, and Q <- P+Q = (XQP:ZQP) such that = x(Q+P)=XQP/ZQP.
    internal void XDblAdd(PointProj P, PointProj Q, ulong[][] xPQ, ulong[][] A24)
    {
        ulong[][] t0 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            t1 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            t2 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD);

        engine.fpx.mp2_add(P.X, P.Z, t0);                  // t0 = XP+ZP
        engine.fpx.mp2_sub_p2(P.X, P.Z, t1);               // t1 = XP-ZP
        engine.fpx.fp2sqr_mont(t0, P.X);                   // XP = (XP+ZP)^2
        engine.fpx.mp2_sub_p2(Q.X, Q.Z, t2);               // t2 = XQ-ZQ
        engine.fpx.mp2_add(Q.X, Q.Z, Q.X);                 // XQ = XQ+ZQ
        engine.fpx.fp2mul_mont(t0, t2, t0);                // t0 = (XP+ZP)*(XQ-ZQ)
        engine.fpx.fp2sqr_mont(t1, P.Z);                   // ZP = (XP-ZP)^2
        engine.fpx.fp2mul_mont(t1, Q.X, t1);               // t1 = (XP-ZP)*(XQ+ZQ)
        engine.fpx.mp2_sub_p2(P.X, P.Z, t2);               // t2 = (XP+ZP)^2-(XP-ZP)^2
        engine.fpx.fp2mul_mont(P.X, P.Z, P.X);             // XP = (XP+ZP)^2*(XP-ZP)^2
        engine.fpx.fp2mul_mont(A24, t2, Q.X);              // XQ = A24*[(XP+ZP)^2-(XP-ZP)^2]
        engine.fpx.mp2_sub_p2(t0, t1, Q.Z);                // ZQ = (XP+ZP)*(XQ-ZQ)-(XP-ZP)*(XQ+ZQ)
        engine.fpx.mp2_add(Q.X, P.Z, P.Z);                 // ZP = A24*[(XP+ZP)^2-(XP-ZP)^2]+(XP-ZP)^2
        engine.fpx.mp2_add(t0, t1, Q.X);                   // XQ = (XP+ZP)*(XQ-ZQ)+(XP-ZP)*(XQ+ZQ)
        engine.fpx.fp2mul_mont(P.Z, t2, P.Z);              // ZP = [A24*[(XP+ZP)^2-(XP-ZP)^2]+(XP-ZP)^2]*[(XP+ZP)^2-(XP-ZP)^2]
        engine.fpx.fp2sqr_mont(Q.Z, Q.Z);                  // ZQ = [(XP+ZP)*(XQ-ZQ)-(XP-ZP)*(XQ+ZQ)]^2
        engine.fpx.fp2sqr_mont(Q.X, Q.X);                  // XQ = [(XP+ZP)*(XQ-ZQ)+(XP-ZP)*(XQ+ZQ)]^2
        engine.fpx.fp2mul_mont(Q.Z, xPQ, Q.Z);             // ZQ = xPQ*[(XP+ZP)*(XQ-ZQ)-(XP-ZP)*(XQ+ZQ)]^2
    }

    // Computes [2^e](X:Z) on Montgomery curve with projective constant via e repeated doublings.
    // Input: projective Montgomery x-coordinates P = (XP:ZP), such that xP=XP/ZP and Montgomery curve constants A+2C and 4C.
    // Output: projective Montgomery x-coordinates Q <- (2^e)*P.
    internal void XDblE(PointProj P, PointProj Q, ulong[][] A24plus, ulong[][] C24, uint e)
    {
        int i;
        engine.fpx.copy_words(P, Q);

        for (i = 0; i < e; i++)
        {
            XDbl(Q, Q, A24plus, C24);
        }
    }

    // Doubling of a Montgomery point in projective coordinates (X:Z).
    // Input: projective Montgomery x-coordinates P = (X1:Z1), where x1=X1/Z1 and Montgomery curve constants A+2C and 4C.
    // Output: projective Montgomery x-coordinates Q = 2*P = (X2:Z2).
    internal void XDbl(PointProj P, PointProj Q, ulong[][] A24plus, ulong[][] C24)
    {
        ulong[][] t0 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            t1 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD);

        engine.fpx.mp2_sub_p2(P.X, P.Z, t0);                // t0 = X1-Z1
        engine.fpx.mp2_add(P.X, P.Z, t1);                   // t1 = X1+Z1
        engine.fpx.fp2sqr_mont(t0, t0);                     // t0 = (X1-Z1)^2
        engine.fpx.fp2sqr_mont(t1, t1);                     // t1 = (X1+Z1)^2
        engine.fpx.fp2mul_mont(C24, t0, Q.Z);               // Z2 = C24*(X1-Z1)^2
        engine.fpx.fp2mul_mont(t1, Q.Z, Q.X);               // X2 = C24*(X1-Z1)^2*(X1+Z1)^2
        engine.fpx.mp2_sub_p2(t1, t0, t1);                  // t1 = (X1+Z1)^2-(X1-Z1)^2
        engine.fpx.fp2mul_mont(A24plus, t1, t0);            // t0 = A24plus*[(X1+Z1)^2-(X1-Z1)^2]
        engine.fpx.mp2_add(Q.Z, t0, Q.Z);                   // Z2 = A24plus*[(X1+Z1)^2-(X1-Z1)^2] + C24*(X1-Z1)^2
        engine.fpx.fp2mul_mont(Q.Z, t1, Q.Z);               // Z2 = [A24plus*[(X1+Z1)^2-(X1-Z1)^2] + C24*(X1-Z1)^2]*[(X1+Z1)^2-(X1-Z1)^2]
    }

    // Tripling of a Montgomery point in projective coordinates (X:Z).
    // Input: projective Montgomery x-coordinates P = (X:Z), where x=X/Z and Montgomery curve constants A24plus = A+2C and A24minus = A-2C.
    // Output: projective Montgomery x-coordinates Q = 3*P = (X3:Z3).
    private void XTpl(PointProj P, PointProj Q, ulong[][] A24minus, ulong[][] A24plus)
    {
        ulong[][] t0 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            t1 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            t2 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            t3 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            t4 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            t5 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            t6 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD);

        engine.fpx.mp2_sub_p2(P.X, P.Z, t0);               // t0 = X-Z
        engine.fpx.fp2sqr_mont(t0, t2);                    // t2 = (X-Z)^2
        engine.fpx.mp2_add(P.X, P.Z, t1);                  // t1 = X+Z
        engine.fpx.fp2sqr_mont(t1, t3);                    // t3 = (X+Z)^2
        engine.fpx.mp2_add(P.X, P.X, t4);                  // t4 = 2*X
        engine.fpx.mp2_add(P.Z, P.Z, t0);                  // t0 = 2*Z
        engine.fpx.fp2sqr_mont(t4, t1);                    // t1 = 4*X^2
        engine.fpx.mp2_sub_p2(t1, t3, t1);                 // t1 = 4*X^2 - (X+Z)^2
        engine.fpx.mp2_sub_p2(t1, t2, t1);                 // t1 = 4*X^2 - (X+Z)^2 - (X-Z)^2
        engine.fpx.fp2mul_mont(A24plus, t3, t5);           // t5 = A24plus*(X+Z)^2
        engine.fpx.fp2mul_mont(t3, t5, t3);                // t3 = A24plus*(X+Z)^4
        engine.fpx.fp2mul_mont(A24minus, t2, t6);          // t6 = A24minus*(X-Z)^2
        engine.fpx.fp2mul_mont(t2, t6, t2);                // t2 = A24minus*(X-Z)^4
        engine.fpx.mp2_sub_p2(t2, t3, t3);                 // t3 = A24minus*(X-Z)^4 - A24plus*(X+Z)^4
        engine.fpx.mp2_sub_p2(t5, t6, t2);                 // t2 = A24plus*(X+Z)^2 - A24minus*(X-Z)^2
        engine.fpx.fp2mul_mont(t1, t2, t1);                // t1 = [4*X^2 - (X+Z)^2 - (X-Z)^2]*[A24plus*(X+Z)^2 - A24minus*(X-Z)^2]
        engine.fpx.fp2add(t3, t1, t2);                     // t2 = [4*X^2 - (X+Z)^2 - (X-Z)^2]*[A24plus*(X+Z)^2 - A24minus*(X-Z)^2] + A24minus*(X-Z)^4 - A24plus*(X+Z)^4
        engine.fpx.fp2sqr_mont(t2, t2);                    // t2 = t2^2
        engine.fpx.fp2mul_mont(t4, t2, Q.X);               // X3 = 2*X*t2
        engine.fpx.fp2sub(t3, t1, t1);                     // t1 = A24minus*(X-Z)^4 - A24plus*(X+Z)^4 - [4*X^2 - (X+Z)^2 - (X-Z)^2]*[A24plus*(X+Z)^2 - A24minus*(X-Z)^2]
        engine.fpx.fp2sqr_mont(t1, t1);                    // t1 = t1^2
        engine.fpx.fp2mul_mont(t0, t1, Q.Z);               // Z3 = 2*Z*t1
    }

    // Computes [3^e](X:Z) on Montgomery curve with projective constant via e repeated triplings.
    // Input: projective Montgomery x-coordinates P = (XP:ZP), such that xP=XP/ZP and Montgomery curve constants A24plus = A+2C and A24minus = A-2C.
    // Output: projective Montgomery x-coordinates Q <- (3^e)*P.
    internal void XTplE(PointProj P, PointProj Q, ulong[][] A24minus, ulong[][] A24plus, uint e)
    {
        int i;
        engine.fpx.copy_words(P, Q);
        for (i = 0; i < e; i++)
        {
            XTpl(Q, Q, A24minus, A24plus);
        }
    }

    // Given the x-coordinates of P, Q, and R, returns the value A corresponding to the Montgomery curve E_A: y^2=x^3+A*x^2+x such that R=Q-P on E_A.
    // Input:  the x-coordinates xP, xQ, and xR of the points P, Q and R.
    // Output: the coefficient A corresponding to the curve E_A: y^2=x^3+A*x^2+x.
    internal void GetA(ulong[][] xP, ulong[][] xQ, ulong[][] xR, ulong[][] A)
    {
        ulong[][] t0 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            t1 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            one = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD);

        engine.fpx.fpcopy(engine.param.Montgomery_one, 0, one[0]);
        engine.fpx.fp2add(xP, xQ, t1);                     // t1 = xP+xQ
        engine.fpx.fp2mul_mont(xP, xQ, t0);                // t0 = xP*xQ
        engine.fpx.fp2mul_mont(xR, t1, A);                 // A = xR*t1
        engine.fpx.fp2add(t0, A, A);                       // A = A+t0
        engine.fpx.fp2mul_mont(t0, xR, t0);                // t0 = t0*xR
        engine.fpx.fp2sub(A, one, A);                      // A = A-1
        engine.fpx.fp2add(t0, t0, t0);                     // t0 = t0+t0
        engine.fpx.fp2add(t1, xR, t1);                     // t1 = t1+xR
        engine.fpx.fp2add(t0, t0, t0);                     // t0 = t0+t0
        engine.fpx.fp2sqr_mont(A, A);                      // A = A^2
        engine.fpx.fp2inv_mont(t0);                        // t0 = 1/t0
        engine.fpx.fp2mul_mont(A, t0, A);                  // A = A*t0
        engine.fpx.fp2sub(A, t1, A);                       // A= A-t1
    }

    // Computes the j-invariant of a Montgomery curve with projective constant.
    // Input: A,C in GF(p^2).
    // Output: j=256*(A^2-3*C^2)^3/(C^4*(A^2-4*C^2)), which is the j-invariant of the Montgomery curve B*y^2=x^3+(A/C)*x^2+x or (equivalently) j-invariant of B'*y^2=C*x^3+A*x^2+C*x.
    internal void JInv(ulong[][] A, ulong[][] C, ulong[][] jinv)
    {
        ulong[][] t0 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            t1 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD);
        
        engine.fpx.fp2sqr_mont(A, jinv);                   // jinv = A^2
        engine.fpx.fp2sqr_mont(C, t1);                     // t1 = C^2
        engine.fpx.fp2add(t1, t1, t0);                     // t0 = t1+t1
        engine.fpx.fp2sub(jinv, t0, t0);                   // t0 = jinv-t0
        engine.fpx.fp2sub(t0, t1, t0);                     // t0 = t0-t1
        engine.fpx.fp2sub(t0, t1, jinv);                   // jinv = t0-t1
        engine.fpx.fp2sqr_mont(t1, t1);                    // t1 = t1^2
        engine.fpx.fp2mul_mont(jinv, t1, jinv);            // jinv = jinv*t1
        engine.fpx.fp2add(t0, t0, t0);                     // t0 = t0+t0
        engine.fpx.fp2add(t0, t0, t0);                     // t0 = t0+t0
        engine.fpx.fp2sqr_mont(t0, t1);                    // t1 = t0^2
        engine.fpx.fp2mul_mont(t0, t1, t0);                // t0 = t0*t1
        engine.fpx.fp2add(t0, t0, t0);                     // t0 = t0+t0
        engine.fpx.fp2add(t0, t0, t0);                     // t0 = t0+t0
        engine.fpx.fp2inv_mont(jinv);                      // jinv = 1/jinv
        engine.fpx.fp2mul_mont(jinv, t0, jinv);            // jinv = t0*jinv
    }



    // Computes the corresponding 3-isogeny of a projective Montgomery point (X3:Z3) of order 3.
    // Input:  projective point of order three P = (X3:Z3).
    // Output: the 3-isogenous Montgomery curve with projective coefficient A/C.
    internal void Get3Isog(PointProj P, ulong[][] A24minus, ulong[][] A24plus, ulong[][][] coeff)
    {
        ulong[][] t0 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            t1 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            t2 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            t3 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            t4 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD);

        engine.fpx.mp2_sub_p2(P.X, P.Z, coeff[0]);         // coeff0 = X-Z
        engine.fpx.fp2sqr_mont(coeff[0], t0);              // t0 = (X-Z)^2
        engine.fpx.mp2_add(P.X, P.Z, coeff[1]);            // coeff1 = X+Z
        engine.fpx.fp2sqr_mont(coeff[1], t1);              // t1 = (X+Z)^2
        engine.fpx.mp2_add(P.X, P.X, t3);                  // t3 = 2*X
        engine.fpx.fp2sqr_mont(t3, t3);                    // t3 = 4*X^2
        engine.fpx.fp2sub(t3, t0, t2);                     // t2 = 4*X^2 - (X-Z)^2
        engine.fpx.fp2sub(t3, t1, t3);                     // t3 = 4*X^2 - (X+Z)^2
        engine.fpx.mp2_add(t0, t3, t4);                    // t4 = 4*X^2 - (X+Z)^2 + (X-Z)^2
        engine.fpx.mp2_add(t4, t4, t4);                    // t4 = 2(4*X^2 - (X+Z)^2 + (X-Z)^2)
        engine.fpx.mp2_add(t1, t4, t4);                    // t4 = 8*X^2 - (X+Z)^2 + 2*(X-Z)^2
        engine.fpx.fp2mul_mont(t2, t4, A24minus);          // A24minus = [4*X^2 - (X-Z)^2]*[8*X^2 - (X+Z)^2 + 2*(X-Z)^2]
        engine.fpx.mp2_add(t1, t2, t4);                    // t4 = 4*X^2 + (X+Z)^2 - (X-Z)^2
        engine.fpx.mp2_add(t4, t4, t4);                    // t4 = 2(4*X^2 + (X+Z)^2 - (X-Z)^2)
        engine.fpx.mp2_add(t0, t4, t4);                    // t4 = 8*X^2 + 2*(X+Z)^2 - (X-Z)^2
        engine.fpx.fp2mul_mont(t3, t4, A24plus);           // A24plus = [4*X^2 - (X+Z)^2]*[8*X^2 + 2*(X+Z)^2 - (X-Z)^2]
    }

    // Computes the 3-isogeny R=phi(X:Z), given projective point (X3:Z3) of order 3 on a Montgomery curve and
    // a point P with 2 coefficients in coeff (computed in the function get_3_Isog()).
    // Inputs: projective points P = (X3:Z3) and Q = (X:Z).
    // Output: the projective point Q <- phi(Q) = (X3:Z3).
    internal void Eval3Isog(PointProj Q, ulong[][][] coeff)
    {
        ulong[][] t0 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            t1 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            t2 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD);

        engine.fpx.mp2_add(Q.X, Q.Z, t0);                  // t0 = X+Z
        engine.fpx.mp2_sub_p2(Q.X, Q.Z, t1);               // t1 = X-Z
        engine.fpx.fp2mul_mont(coeff[0], t0, t0);          // t0 = coeff0*(X+Z)
        engine.fpx.fp2mul_mont(coeff[1], t1, t1);          // t1 = coeff1*(X-Z)
        engine.fpx.mp2_add(t0, t1, t2);                    // t2 = coeff0*(X+Z) + coeff1*(X-Z)
        engine.fpx.mp2_sub_p2(t1, t0, t0);                 // t0 = coeff1*(X-Z) - coeff0*(X+Z)
        engine.fpx.fp2sqr_mont(t2, t2);                    // t2 = [coeff0*(X+Z) + coeff1*(X-Z)]^2
        engine.fpx.fp2sqr_mont(t0, t0);                    // t0 = [coeff1*(X-Z) - coeff0*(X+Z)]^2
        engine.fpx.fp2mul_mont(Q.X, t2, Q.X);              // X3= X*[coeff0*(X+Z) + coeff1*(X-Z)]^2
        engine.fpx.fp2mul_mont(Q.Z, t0, Q.Z);              // Z3= Z*[coeff1*(X-Z) - coeff0*(X+Z)]^2
    }

    // 3-way simultaneous inversion
    // Input:  z1,z2,z3
    // Output: 1/z1,1/z2,1/z3 (override inputs).
    internal void Inv3Way(ulong[][] z1, ulong[][] z2, ulong[][] z3)
    {
        ulong[][] t0 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            t1 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            t2 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            t3 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD);

        engine.fpx.fp2mul_mont(z1, z2, t0);                // t0 = z1*z2
        engine.fpx.fp2mul_mont(z3, t0, t1);                // t1 = z1*z2*z3
        engine.fpx.fp2inv_mont(t1);                        // t1 = 1/(z1*z2*z3)
        engine.fpx.fp2mul_mont(z3, t1, t2);                // t2 = 1/(z1*z2)
        engine.fpx.fp2mul_mont(t2, z2, t3);                // t3 = 1/z1
        engine.fpx.fp2mul_mont(t2, z1, z2);                // z2 = 1/z2
        engine.fpx.fp2mul_mont(t0, t1, z3);                // z3 = 1/z3
        engine.fpx.fp2copy(t3, z1);                        // z1 = 1/z1
    }

    // Computes the corresponding 2-isogeny of a projective Montgomery point (X2:Z2) of order 2.
    // Input:  projective point of order two P = (X2:Z2).
    // Output: the 2-isogenous Montgomery curve with projective coefficients A/C.
    internal void Get2Isog(PointProj P, ulong[][] A, ulong[][] C)
    {
        engine.fpx.fp2sqr_mont(P.X, A);                    // A = X2^2
        engine.fpx.fp2sqr_mont(P.Z, C);                    // C = Z2^2
        engine.fpx.mp2_sub_p2(C, A, A);                    // A = Z2^2 - X2^2
    }

    // Evaluates the isogeny at the point (X:Z) in the domain of the isogeny, given a 2-isogeny phi.
    // Inputs: the projective point P = (X:Z) and the 2-isogeny kernel projetive point Q = (X2:Z2).
    // Output: the projective point P = phi(P) = (X:Z) in the codomain. 
    internal void Eval2Isog(PointProj P, PointProj Q)
    {
        ulong[][] t0 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            t1 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            t2 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            t3 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD);

        engine.fpx.mp2_add(Q.X, Q.Z, t0);                  // t0 = X2+Z2
        engine.fpx.mp2_sub_p2(Q.X, Q.Z, t1);               // t1 = X2-Z2
        engine.fpx.mp2_add(P.X, P.Z, t2);                  // t2 = X+Z
        engine.fpx.mp2_sub_p2(P.X, P.Z, t3);               // t3 = X-Z
        engine.fpx.fp2mul_mont(t0, t3, t0);                // t0 = (X2+Z2)*(X-Z)
        engine.fpx.fp2mul_mont(t1, t2, t1);                // t1 = (X2-Z2)*(X+Z)
        engine.fpx.mp2_add(t0, t1, t2);                    // t2 = (X2+Z2)*(X-Z) + (X2-Z2)*(X+Z)
        engine.fpx.mp2_sub_p2(t0, t1, t3);                 // t3 = (X2+Z2)*(X-Z) - (X2-Z2)*(X+Z)
        engine.fpx.fp2mul_mont(P.X, t2, P.X);              // Xfinal
        engine.fpx.fp2mul_mont(P.Z, t3, P.Z);              // Zfinal
    }

    // Computes the corresponding 4-isogeny of a projective Montgomery point (X4:Z4) of order 4.
    // Input:  projective point of order four P = (X4:Z4).
    // Output: the 4-isogenous Montgomery curve with projective coefficients A+2C/4C and the 3 coefficients
    //         that are used to evaluate the isogeny at a point in eval_4_Isog().
    internal void Get4Isog(PointProj P, ulong[][] A24plus, ulong[][] C24, ulong[][][] coeff)
    {
        engine.fpx.mp2_sub_p2(P.X, P.Z, coeff[1]);         // coeff[1] = X4-Z4
        engine.fpx.mp2_add(P.X, P.Z, coeff[2]);            // coeff[2] = X4+Z4
        engine.fpx.fp2sqr_mont(P.Z, coeff[0]);             // coeff[0] = Z4^2
        engine.fpx.mp2_add(coeff[0], coeff[0], coeff[0]);  // coeff[0] = 2*Z4^2
        engine.fpx.fp2sqr_mont(coeff[0], C24);             // C24 = 4*Z4^4
        engine.fpx.mp2_add(coeff[0], coeff[0], coeff[0]);  // coeff[0] = 4*Z4^2
        engine.fpx.fp2sqr_mont(P.X, A24plus);              // A24plus = X4^2
        engine.fpx.mp2_add(A24plus, A24plus, A24plus);     // A24plus = 2*X4^2
        engine.fpx.fp2sqr_mont(A24plus, A24plus);          // A24plus = 4*X4^4
    }

    // Evaluates the isogeny at the point (X:Z) in the domain of the isogeny, given a 4-isogeny phi defined
    // by the 3 coefficients in coeff (computed in the function get_4_Isog()).
    // Inputs: the coefficients defining the isogeny, and the projective point P = (X:Z).
    // Output: the projective point P = phi(P) = (X:Z) in the codomain.
    internal void Eval4Isog(PointProj P, ulong[][][] coeff)
    {
        ulong[][] t0 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD),
            t1 = SikeUtilities.InitArray(2, engine.param.NWORDS_FIELD);

        engine.fpx.mp2_add(P.X, P.Z, t0);                  // t0 = X+Z
        engine.fpx.mp2_sub_p2(P.X, P.Z, t1);               // t1 = X-Z
        engine.fpx.fp2mul_mont(t0, coeff[1], P.X);         // X = (X+Z)*coeff[1]
        engine.fpx.fp2mul_mont(t1, coeff[2], P.Z);         // Z = (X-Z)*coeff[2]
        engine.fpx.fp2mul_mont(t0, t1, t0);                // t0 = (X+Z)*(X-Z)
        engine.fpx.fp2mul_mont(coeff[0], t0, t0);          // t0 = coeff[0]*(X+Z)*(X-Z)
        engine.fpx.mp2_add(P.X, P.Z, t1);                  // t1 = (X-Z)*coeff[2] + (X+Z)*coeff[1]
        engine.fpx.mp2_sub_p2(P.X, P.Z, P.Z);              // Z = (X-Z)*coeff[2] - (X+Z)*coeff[1]
        engine.fpx.fp2sqr_mont(t1, t1);                    // t1 = [(X-Z)*coeff[2] + (X+Z)*coeff[1]]^2
        engine.fpx.fp2sqr_mont(P.Z, P.Z);                  // Z = [(X-Z)*coeff[2] - (X+Z)*coeff[1]]^2
        engine.fpx.mp2_add(t1, t0, P.X);                   // X = coeff[0]*(X+Z)*(X-Z) + [(X-Z)*coeff[2] + (X+Z)*coeff[1]]^2
        engine.fpx.mp2_sub_p2(P.Z, t0, t0);                // t0 = [(X-Z)*coeff[2] - (X+Z)*coeff[1]]^2 - coeff[0]*(X+Z)*(X-Z)
        engine.fpx.fp2mul_mont(P.X, t1, P.X);              // Xfinal
        engine.fpx.fp2mul_mont(P.Z, t0, P.Z);              // Zfinal
    }
}
}
