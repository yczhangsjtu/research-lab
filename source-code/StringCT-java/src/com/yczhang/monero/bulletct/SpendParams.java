package com.yczhang.monero.bulletct;

import how.monero.hodl.crypto.Curve25519Point;
import how.monero.hodl.crypto.Curve25519PointPair;
import how.monero.hodl.crypto.Scalar;

public class SpendParams {
  public int iAsterisk;
  public Curve25519PointPair[][] pk;
  public BulletRingCT.SK[] sk;
  public Curve25519Point[] out;
  public Scalar[] output;
}
