package how.monero.hodl.bulletproof;

import how.monero.hodl.crypto.Curve25519Point;
import how.monero.hodl.crypto.Scalar;
import how.monero.hodl.crypto.CryptoUtil;

import static how.monero.hodl.crypto.Scalar.randomScalar;
import static how.monero.hodl.crypto.CryptoUtil.*;
import static how.monero.hodl.util.ByteUtil.*;

public class InnerProductArgument {
    private static int N = 4;
    private static int logN;
    private static Curve25519Point G;
    private static Curve25519Point H;
    private static Curve25519Point U;
    private static Curve25519Point[] Gi;
    private static Curve25519Point[] Hi;
    
    static {
        // Set the curve base points
        G = Curve25519Point.G;
        H = Curve25519Point.hashToPoint(G);
        U = Curve25519Point.hashToPoint(H);
        Gi = new Curve25519Point[N];
        Hi = new Curve25519Point[N];
    	logN = (int)Math.round(Math.log(N)/Math.log(2));
        
        for (int i = 0; i < N; i++)
        {
            Gi[i] = getHpnGLookup(2*i);
            Hi[i] = getHpnGLookup(2*i+1);
        }
    }
    
    public static void setN(int n) {
    	N = n;
        Gi = new Curve25519Point[N];
        Hi = new Curve25519Point[N];
    	logN = (int)Math.round(Math.log(N)/Math.log(2));
        for (int i = 0; i < N; i++)
        {
            Gi[i] = getHpnGLookup(2*i);
            Hi[i] = getHpnGLookup(2*i+1);
        }
    }
    
    public static class InnerProductProofTuple {
        private Curve25519Point[] L;
        private Curve25519Point[] R;
        private Scalar a;
        private Scalar b;
        
    	public InnerProductProofTuple(Curve25519Point[] L, Curve25519Point[] R, Scalar a, Scalar b) {
            this.L = L;
            this.R = R;
            this.a = a;
            this.b = b;
    	}

		public int size() {
			int ret = 0;
			for(int i = 0; i < L.length; i++)
				ret += L[i].toBytes().length;
			for(int i = 0; i < R.length; i++)
				ret += R[i].toBytes().length;
			ret += this.a.bytes.length;
			ret += this.b.bytes.length;
			return ret;
		}

		public byte[] toBytes() {
			byte[] ret = concat(this.a.bytes,this.b.bytes);
			for(int i = 0; i < this.L.length; i++)
				ret = concat(ret, this.L[i].toBytes());
			for(int i = 0; i < this.R.length; i++)
				ret = concat(ret, this.R[i].toBytes());
			return ret;
		}
    }
    
    /* Given two scalar arrays, construct a vector commitment */
    public static Curve25519Point VectorExponent(Scalar[] a, Scalar[] b)
    {
        assert a.length == N && b.length == N;

        Curve25519Point Result = Curve25519Point.ZERO;
        for (int i = 0; i < N; i++)
        {
            Result = Result.add(Gi[i].scalarMultiply(a[i]));
            Result = Result.add(Hi[i].scalarMultiply(b[i]));
        }
        return Result;
    }

    /* Compute a custom vector-scalar commitment */
    public static Curve25519Point VectorExponentCustom(Curve25519Point[] A, Curve25519Point[] B, Scalar[] a, Scalar[] b)
    {
        assert a.length == A.length && b.length == B.length && a.length == b.length;

        Curve25519Point Result = Curve25519Point.ZERO;
        for (int i = 0; i < a.length; i++)
        {
            Result = Result.add(A[i].scalarMultiply(a[i]));
            Result = Result.add(B[i].scalarMultiply(b[i]));
        }
        return Result;
    }

    /* Given a scalar, construct a vector of powers */
    public static Scalar[] VectorPowers(Scalar x)
    {
        Scalar[] result = new Scalar[N];
        for (int i = 0; i < N; i++)
        {
            result[i] = x.pow(i);
        }
        return result;
    }

    /* Given two scalar arrays, construct the inner product */
    public static Scalar InnerProduct(Scalar[] a, Scalar[] b)
    {
        assert a.length == b.length;

        Scalar result = Scalar.ZERO;
        for (int i = 0; i < a.length; i++)
        {
            result = result.add(a[i].mul(b[i]));
        }
        return result;
    }

    /* Given two scalar arrays, construct the Hadamard product */
    public static Scalar[] Hadamard(Scalar[] a, Scalar[] b)
    {
        assert a.length == b.length;

        Scalar[] result = new Scalar[a.length];
        for (int i = 0; i < a.length; i++)
        {
            result[i] = a[i].mul(b[i]);
        }
        return result;
    }

    /* Given two curvepoint arrays, construct the Hadamard product */
    public static Curve25519Point[] Hadamard2(Curve25519Point[] A, Curve25519Point[] B)
    {
        assert A.length == B.length;

        Curve25519Point[] Result = new Curve25519Point[A.length];
        for (int i = 0; i < A.length; i++)
        {
            Result[i] = A[i].add(B[i]);
        }
        return Result;
    }

    /* Add two vectors */
    public static Scalar[] VectorAdd(Scalar[] a, Scalar[] b)
    {
        assert a.length == b.length;

        Scalar[] result = new Scalar[a.length];
        for (int i = 0; i < a.length; i++)
        {
            result[i] = a[i].add(b[i]);
        }
        return result;
    }
    
    /* Subtract two vectors */
    public static Scalar[] VectorSubtract(Scalar[] a, Scalar[] b)
    {
        assert a.length == b.length;

        Scalar[] result = new Scalar[a.length];
        for (int i = 0; i < a.length; i++)
        {
            result[i] = a[i].sub(b[i]);
        }
        return result;
    }

    /* Multiply a scalar and a vector */
    public static Scalar[] VectorScalar(Scalar[] a, Scalar x)
    {
        Scalar[] result = new Scalar[a.length];
        for (int i = 0; i < a.length; i++)
        {
            result[i] = a[i].mul(x);
        }
        return result;
    }

    /* Exponentiate a curve vector by a scalar */
    public static Curve25519Point[] VectorScalar2(Curve25519Point[] A, Scalar x)
    {
        Curve25519Point[] Result = new Curve25519Point[A.length];
        for (int i = 0; i < A.length; i++)
        {
            Result[i] = A[i].scalarMultiply(x);
        }
        return Result;
    }

    /* Compute the inverse of a scalar, the stupid way */
    public static Scalar Invert(Scalar x)
    {
        Scalar inverse = new Scalar(x.toBigInteger().modInverse(CryptoUtil.l));

        assert x.mul(inverse).equals(Scalar.ONE);
        return inverse;
    }

    /* Compute the slice of a curvepoint vector */
    public static Curve25519Point[] CurveSlice(Curve25519Point[] a, int start, int stop)
    {
        Curve25519Point[] Result = new Curve25519Point[stop-start];
        for (int i = start; i < stop; i++)
        {
            Result[i-start] = a[i];
        }
        return Result;
    }

    /* Compute the slice of a scalar vector */
    public static Scalar[] ScalarSlice(Scalar[] a, int start, int stop)
    {
        Scalar[] result = new Scalar[stop-start];
        for (int i = start; i < stop; i++)
        {
            result[i-start] = a[i];
        }
        return result;
    }

    public static InnerProductProofTuple InnerProductProve(Scalar[] a, Scalar[] b, Curve25519Point[] Gprime, Curve25519Point[] Hprime, Curve25519Point u, Scalar seed)
    {
        // These are used in the inner product rounds
        int nprime = N;
        Curve25519Point[] L = new Curve25519Point[logN];
        Curve25519Point[] R = new Curve25519Point[logN];
        int round = 0; // track the index based on number of rounds
        Scalar[] w = new Scalar[logN]; // this is the challenge x in the inner product protocol

        // PAPER LINE 13
        while (nprime > 1)
        {
            // PAPER LINE 15
            nprime /= 2;

            // PAPER LINES 16-17
            Scalar cL = InnerProduct(ScalarSlice(a,0,nprime),ScalarSlice(b,nprime,b.length));
            Scalar cR = InnerProduct(ScalarSlice(a,nprime,a.length),ScalarSlice(b,0,nprime));

            // PAPER LINES 18-19
            L[round] = VectorExponentCustom(CurveSlice(Gprime,nprime,Gprime.length),CurveSlice(Hprime,0,nprime),ScalarSlice(a,0,nprime),ScalarSlice(b,nprime,b.length)).add(u.scalarMultiply(cL));
            R[round] = VectorExponentCustom(CurveSlice(Gprime,0,nprime),CurveSlice(Hprime,nprime,Hprime.length),ScalarSlice(a,nprime,a.length),ScalarSlice(b,0,nprime)).add(u.scalarMultiply(cR));

            // PAPER LINES 21-22
            seed = hashToScalar(concat(seed.bytes,L[round].toBytes()));
            seed = hashToScalar(concat(seed.bytes,R[round].toBytes()));
            w[round] = seed; // w is the challenge x in paper

            // PAPER LINES 24-25
            Gprime = Hadamard2(VectorScalar2(CurveSlice(Gprime,0,nprime),Invert(w[round])),VectorScalar2(CurveSlice(Gprime,nprime,Gprime.length),w[round]));
            Hprime = Hadamard2(VectorScalar2(CurveSlice(Hprime,0,nprime),w[round]),VectorScalar2(CurveSlice(Hprime,nprime,Hprime.length),Invert(w[round])));

            // PAPER LINES 28-29
            a = VectorAdd(VectorScalar(ScalarSlice(a,0,nprime),w[round]),VectorScalar(ScalarSlice(a,nprime,a.length),Invert(w[round])));
            b = VectorAdd(VectorScalar(ScalarSlice(b,0,nprime),Invert(w[round])),VectorScalar(ScalarSlice(b,nprime,b.length),w[round]));

            round += 1;
        }
        
        return new InnerProductProofTuple(L, R, a[0], b[0]);
    }
    
    public static boolean InnerProductVerify(InnerProductProofTuple proof, Curve25519Point P, Curve25519Point[] Gprime, Curve25519Point[] Hprime, Curve25519Point u, Scalar seed)
    {
        int nprime = N;
        Curve25519Point Pprime = P;
        int rounds = proof.L.length;
        
        Scalar[] w = new Scalar[rounds];
        seed = hashToScalar(concat(seed.bytes,proof.L[0].toBytes()));
        seed = hashToScalar(concat(seed.bytes,proof.R[0].toBytes()));
        w[0] = seed;
        
        if (rounds > 1)
        {
            for (int i = 1; i < rounds; i++)
            {
            	seed = hashToScalar(concat(seed.bytes,proof.L[i].toBytes()));
            	seed = hashToScalar(concat(seed.bytes,proof.R[i].toBytes()));
                w[i] = seed;
            }
        }

        for (int i = 0; i < rounds; i++)
        {
            nprime /= 2;
            
            Pprime = Pprime.add(proof.L[i].scalarMultiply(w[i].sq()));
            Pprime = Pprime.add(proof.R[i].scalarMultiply(Invert(w[i]).sq()));
            
            Gprime = Hadamard2(VectorScalar2(CurveSlice(Gprime,0,nprime),Invert(w[i])),VectorScalar2(CurveSlice(Gprime,nprime,Gprime.length),w[i]));
            Hprime = Hadamard2(VectorScalar2(CurveSlice(Hprime,0,nprime),w[i]),VectorScalar2(CurveSlice(Hprime,nprime,Hprime.length),Invert(w[i])));
        }
        
        Scalar c = proof.a.mul(proof.b);
        if(!Pprime.equals(Gprime[0].scalarMultiply(proof.a).add(Hprime[0].scalarMultiply(proof.b)).add(u.scalarMultiply(c))))
        	return false;
    	return true;
    }
    
    public static InnerProductProofTuple PROVE(Scalar[] a, Scalar[] b, Curve25519Point[] Gprime, Curve25519Point[] Hprime, Scalar seed) {
    	Scalar x = hashToScalar(concat(seed.bytes,U.toBytes()));
    	return InnerProductProve(a,b,Gprime,Hprime,U.scalarMultiply(x),seed);
    }
    
    public static boolean VERIFY(InnerProductProofTuple proof, Curve25519Point P, Curve25519Point[] Gprime, Curve25519Point[] Hprime, Scalar c, Scalar seed) {
    	Scalar x = hashToScalar(concat(seed.bytes,U.toBytes()));
        P = P.add(U.scalarMultiply(c.mul(x)));
    	return InnerProductVerify(proof,P,Gprime,Hprime,U.scalarMultiply(x),seed);
    }

	public static void main(String[] args) {

		Scalar[] a = new Scalar[N];
		Scalar[] b = new Scalar[N];
        // Run a bunch of randomized trials
        int TRIALS = 10;
        
        Curve25519Point P = Curve25519Point.ZERO;

        for (int count = 0; count < TRIALS; count++)
        {
            Scalar seed = randomScalar();
            for (int i = 0; i < N; i++)
            {
                a[i] = randomScalar();
                b[i] = randomScalar();
            }
            P = VectorExponentCustom(Gi,Hi,a,b);
            Scalar c = InnerProduct(a,b);
            P = P.add(U.scalarMultiply(c));

            InnerProductProofTuple proof = InnerProductProve(a,b,Gi,Hi,U,seed);
            if (!InnerProductVerify(proof,P,Gi,Hi,U,seed))
                System.out.println("Test failed");
            else
                System.out.println("Test succeeded");
        }

        for (int count = 0; count < TRIALS; count++)
        {
            Scalar seed = randomScalar();
            for (int i = 0; i < N; i++)
            {
                a[i] = randomScalar();
                b[i] = randomScalar();
            }
            P = VectorExponentCustom(Gi,Hi,a,b);
            Scalar c = InnerProduct(a,b);

            InnerProductProofTuple proof = PROVE(a,b,Gi,Hi,seed);
            if (!VERIFY(proof,P,Gi,Hi,c,seed))
                System.out.println("Test failed");
            else
                System.out.println("Test succeeded");

        }
	}

}
