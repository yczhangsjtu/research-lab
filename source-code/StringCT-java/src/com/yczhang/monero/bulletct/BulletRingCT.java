package com.yczhang.monero.bulletct;

import static how.monero.hodl.util.ByteUtil.bytesToHex;

import how.monero.hodl.bulletproof.MembershipProof;
import how.monero.hodl.bulletproof.OptimizedLogBulletproof;
import how.monero.hodl.crypto.Curve25519Point;
import how.monero.hodl.crypto.Curve25519PointPair;
import how.monero.hodl.crypto.Scalar;
import how.monero.hodl.ringSignature.StringCT.KeyGenResult;
import how.monero.hodl.ringSignature.StringCT.SpendSignature;

import static how.monero.hodl.ringSignature.StringCT.KEYGEN;
import static how.monero.hodl.crypto.Scalar.randomScalar;

public class BulletRingCT {
	public static class SK {
		Scalar sk;
		Scalar m;
		Scalar r;
		
	    public SK(Scalar sk, Scalar m, Scalar r) {
	        this.r = r;
	        this.sk = sk;
	        this.m = m;
	    }

	    @Override
	    public String toString() {
	    	return "(sk: " + bytesToHex(sk) + ", m: " + bytesToHex(m) + ", r: " + bytesToHex(r) + ")";
	    }
	}
	
	public static class SpendSignature {
		public MembershipProof.ProofTuple sigma;
		public OptimizedLogBulletproof.ProofTuple pi;
		public Curve25519Point S3;
		public Curve25519Point[] U;
		public Curve25519PointPair[] AR;
		public SpendSignature(MembershipProof.ProofTuple sigma, OptimizedLogBulletproof.ProofTuple pi,
				Curve25519Point s3, Curve25519Point[] u, Curve25519PointPair[] ar) {
			this.sigma = sigma;
			this.pi = pi;
			S3 = s3;
			U = u;
			AR = ar;
		}
	}
	
	public static SpendSignature SPEND(SpendParams sp) {
		Curve25519Point G = Curve25519Point.G;
		Curve25519Point H = Curve25519Point.hashToPoint(G);
		
		// 1.a Check the balance
		Scalar left = Scalar.ZERO, right = Scalar.ZERO;
		for(SK sk: sp.sk) {
			left = left.add(sk.m);
		}
		for(Scalar o: sp.output) {
			right = right.add(o);
		}
		if(!left.equals(right)) return null;
		
		// 1.b Generate output commitments
		int m = sp.output.length;
		Scalar[] rout = new Scalar[m];
		Scalar routsum = Scalar.ZERO;
		Curve25519Point[] Cout = new Curve25519Point[m];
		Curve25519Point Coutsum = Curve25519Point.ZERO;
		Curve25519PointPair[] AR = new Curve25519PointPair[m];
		for(int i = 0; i < m; i++) {
			rout[i] = randomScalar();
			Cout[i] = G.scalarMultiply(sp.output[i]).add(H.scalarMultiply(rout[i]));
			AR[i] = new Curve25519PointPair(sp.out[i],Cout[i]);
			Coutsum = Coutsum.add(Cout[i]);
			routsum = routsum.add(rout[i]);
		}
		
		// 2. Prepare a set of public keys and a secret key
		int I = sp.pk[0].length, M = sp.pk.length;
		Curve25519Point[] pktilde = new Curve25519Point[I];
		for(int i = 0; i < I; i++) {
			pktilde[i] = Curve25519Point.ZERO;
			for(int k = 0; k < M; k++) pktilde[i] = pktilde[i].add(sp.pk[k][i].P1).add(sp.pk[k][i].P2);
			pktilde[i] = pktilde[i].subtract(Coutsum);
		}
		Scalar sktilde = Scalar.ZERO;
		for(int i = 0; i < M; i++) sktilde = sktilde.add(sp.sk[i].sk).add(sp.sk[i].r);
		sktilde = sktilde.sub(routsum);
	}
}
