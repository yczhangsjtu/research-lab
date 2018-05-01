package com.yczhang.monero.bulletct;

import static how.monero.hodl.util.ByteUtil.bytesToHex;

import how.monero.hodl.bulletproof.MembershipProof;
import how.monero.hodl.bulletproof.OptimizedLogBulletproof;
import how.monero.hodl.crypto.Curve25519Point;
import how.monero.hodl.crypto.Curve25519PointPair;
import how.monero.hodl.crypto.Scalar;

import static how.monero.hodl.crypto.Scalar.randomScalar;
import static how.monero.hodl.crypto.CryptoUtil.hashToScalar;
import static how.monero.hodl.bulletproof.MembershipProof.H5;
import static how.monero.hodl.util.ByteUtil.concat;

import java.math.BigInteger;

public class BulletRingCT {
	
	private static Curve25519Point G = Curve25519Point.G;
	private static Curve25519Point H = Curve25519Point.hashToPoint(Curve25519Point.G);
	
	public static class SK {
		public Scalar sk;
		public Scalar m;
		public Scalar r;
		
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


	public static KeyGenResult KEYGEN(Scalar m) {
		SK sk = new SK(randomScalar(), m, randomScalar());
		Curve25519Point ki = G.scalarMultiply(sk.r);
		Curve25519PointPair pk = new Curve25519PointPair(
				G.scalarMultiply(sk.sk),
				ki.add(H.scalarMultiply(sk.m)));
		return new KeyGenResult(sk, ki, pk);
	}

	public static KeyGenResult KEYGEN(BigInteger m) {
		return KEYGEN(new Scalar(m));
	}

	public static KeyGenResult KEYGEN() {
		return KEYGEN(randomScalar());
	}
	
	public static class KeyGenResult {
		public SK sk;
		public Curve25519Point ki;
		public Curve25519PointPair pk = null;
		public KeyGenResult(SK sk, Curve25519Point ki, Curve25519PointPair pk) {
			this.sk = sk; this.ki = ki; this.pk = pk;
		}

		@Override
		public String toString() {
			return "sk: " + sk.toString() + ", ki: " + bytesToHex(ki.toBytes()) + ", pk: " + (pk==null ? "(no pk)" : "pk: " + pk);
		}
	}
	  
	public static class SpendSignature {
		public MembershipProof.ProofTuple sigma;
		public OptimizedLogBulletproof.ProofTuple[] pi;
		public Curve25519Point S3;
		public Curve25519Point[] U;
		public Curve25519PointPair[] AR;
		public SpendSignature(MembershipProof.ProofTuple sigma, OptimizedLogBulletproof.ProofTuple[] pi,
				Curve25519Point s3, Curve25519Point[] u, Curve25519PointPair[] ar) {
			this.sigma = sigma;
			this.pi = pi;
			S3 = s3;
			U = u;
			AR = ar;
		}
	    public byte[] toBytes() {
	        byte[] result = sigma.toBytes();
	        for(int i = 0; i < pi.length; i++)
	        	result = concat(result, pi[i].toBytes());
	        result = concat(result, S3.toBytes());
	        for(int i = 0; i < U.length; i++)
	        	result = concat(result, U[i].toBytes());
	        return result;
	    }
	}
	
	public static SpendSignature SPEND(SpendParams sp) {
		Curve25519Point u = Curve25519Point.hashToPoint(H);
		
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
			Cout[i] = H.scalarMultiply(sp.output[i]).add(G.scalarMultiply(rout[i]));
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
		
		Scalar seed = Scalar.ZERO;
		for(int i = 0; i < I; i++)
			seed = hashToScalar(concat(seed.bytes,pktilde[i].toBytes()));
		
		Scalar rsk = hashToScalar(seed.bytes);
		Curve25519Point S3 = u.scalarMultiply(rsk);
		
		// 3. Generate key images
		Curve25519Point[] U = new Curve25519Point[M+1];
		for(int i = 0; i < M; i++)
			U[i] = u.scalarMultiply(sp.sk[i].sk);
		U[M] = u.scalarMultiply(sktilde);
		byte[] AARS3 = new byte[] {};
		for(int i = 0; i < M; i++)
			for(int j = 0; j < I; j++)
				AARS3 = concat(AARS3,sp.pk[i][j].toBytes());
		for(int i = 0; i < m; i++)
			AARS3 = concat(AARS3, AR[i].toBytes());
		AARS3 = concat(AARS3, S3.toBytes());
		Scalar v = H5(AARS3);
		Curve25519Point[] Y = new Curve25519Point[I];
		
		for(int i = 0; i < I; i++) {
			Scalar vk = Scalar.ONE;
			Y[i] = Curve25519Point.ZERO;
			for(int j = 0; j < M; j++) {
				Y[i] = Y[i].add(sp.pk[j][i].P1.scalarMultiply(vk));
				vk = vk.mul(v);
			}
			Y[i] = Y[i].add(pktilde[i].scalarMultiply(vk));
		}

		Scalar vk = Scalar.ONE;
		Scalar skstar = Scalar.ZERO;
		for(int k = 0; k < M; k++) {
			skstar = skstar.add(sp.sk[k].sk.mul(vk));
			vk = vk.mul(v);
		}
		skstar = skstar.add(sktilde.mul(vk));
		
		// 4. Generate ring signature
		byte[] text = v.bytes;
		for(int i = 0; i < U.length; i++)
			text = concat(text,U[i].toBytes());
		
		MembershipProof.ProofTuple sigma = MembershipProof.PROVE(Y, sp.iAsterisk, skstar, true, seed, text, S3);
		OptimizedLogBulletproof.ProofTuple[] pi = new OptimizedLogBulletproof.ProofTuple[m];
		for(int i = 0; i < m; i++)
			pi[i] = OptimizedLogBulletproof.PROVE(sp.output[i], rout[i]);
		
		return new SpendSignature(sigma, pi, S3, U, AR);
	}
	
	public static boolean VERIFY(Curve25519PointPair[][] pk, SpendSignature spendSignature) {
		Curve25519Point G = Curve25519Point.G;
		Curve25519Point H = Curve25519Point.hashToPoint(G);
		Curve25519Point u = Curve25519Point.hashToPoint(H);
		
		// 1. Check the serial numbers for double spending
		// TODO: Neglected for now
		
		// 2. Compute pktilde and v, Y
		int I = pk[0].length, M = pk.length, m = spendSignature.AR.length;
		Curve25519Point[] pktilde = new Curve25519Point[I];
		Curve25519Point Coutsum = Curve25519Point.ZERO;
		for(int i = 0; i < spendSignature.AR.length; i++) {
			Coutsum = Coutsum.add(spendSignature.AR[i].P2);
		}
		for(int i = 0; i < I; i++) {
			pktilde[i] = Curve25519Point.ZERO;
			for(int k = 0; k < M; k++) pktilde[i] = pktilde[i].add(pk[k][i].P1).add(pk[k][i].P2);
			pktilde[i] = pktilde[i].subtract(Coutsum);
		}
		
		Scalar seed = Scalar.ZERO;
		for(int i = 0; i < I; i++)
			seed = hashToScalar(concat(seed.bytes,pktilde[i].toBytes()));
		Scalar rsk = hashToScalar(seed.bytes);
		Curve25519Point S3 = u.scalarMultiply(rsk);
		
		byte[] AARS3 = new byte[] {};
		for(int i = 0; i < M; i++)
			for(int j = 0; j < I; j++)
				AARS3 = concat(AARS3,pk[i][j].toBytes());
		for(int i = 0; i < m; i++)
			AARS3 = concat(AARS3, spendSignature.AR[i].toBytes());
		AARS3 = concat(AARS3, S3.toBytes());
		Scalar v = H5(AARS3);
		
		Curve25519Point[] Y = new Curve25519Point[I];
		for(int i = 0; i < I; i++) {
			Scalar vk = Scalar.ONE;
			Y[i] = Curve25519Point.ZERO;
			for(int j = 0; j < M; j++) {
				Y[i] = Y[i].add(pk[j][i].P1.scalarMultiply(vk));
				vk = vk.mul(v);
			}
			Y[i] = Y[i].add(pktilde[i].scalarMultiply(vk));
		}
		
		// 3. Verify sigma and pi
		byte[] text = v.bytes;
		for(int i = 0; i < spendSignature.U.length; i++)
			text = concat(text,spendSignature.U[i].toBytes());
		if(!MembershipProof.VERIFY(spendSignature.sigma, Y, text, S3)) {
			System.out.println("Failed in the membership proof part!");
			return false;
		}
		for(int i = 0; i < m; i++) {
			OptimizedLogBulletproof.VERIFY(spendSignature.pi[i]);
		}
		
		return true;
	}
}
