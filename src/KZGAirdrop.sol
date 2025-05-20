// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { B12, B12_381Lib } from "./B12.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

uint256 constant BLS_MODULUS = 52435875175126190479447740508185965837690552500527637822603658699938581184513;

contract KZGAirdrop is Ownable {
  B12.G1Point private commitment;

  constructor(B12.G1Point memory initialCommitment) Ownable(msg.sender) {
    commitment = initialCommitment;
  }

  function getCommitment() external view returns (B12.G1Point memory) {
    return commitment;
  }

  function checkPairing(B12.G1Point calldata proof, uint256 y, uint256 z) public view returns (bool) {
    B12.G1Point memory p1 = B12_381Lib.g1Add(commitment, B12_381Lib.g1Mul(B12_381Lib.P1(), BLS_MODULUS - y));
    B12.G2Point memory q1 = B12_381Lib.negativeQ1();
    B12.G1Point memory p2 = proof;
    B12.G2Point memory temp = B12_381Lib.Q1();
    B12_381Lib.g2Mul(temp, BLS_MODULUS - z);
    B12.G2Point memory q2 = B12_381Lib.g2Add(B12_381Lib.kzgTrustedSetupG2_1(), temp);
    B12.PairingArg[] memory args = new B12.PairingArg[](2);
    args[0] = B12.PairingArg({ g1: p1, g2: q1 });
    args[1] = B12.PairingArg({ g1: p2, g2: q2 });
    return B12_381Lib.pairing(args);
  }

  event UserBlobUpdated(
    B12.G1Point oldCommitment,
    B12.G1Point newCommitment,
    address user,
    uint256 oldvalue,
    uint256 newvalue
  );

  function updateUserBlob(bytes calldata userInfo, uint256 amount, B12.G1Point calldata proof) external {
    (address user, uint256 value, uint256 z, uint256 x1, uint256 x2, uint256 y1, uint256 y2) = abi.decode(
      userInfo,
      (address, uint256, uint256, uint256, uint256, uint256, uint256)
    );

    uint256 y = uint256(keccak256(userInfo)) % BLS_MODULUS;

    require(checkPairing(proof, y, z), "Pairing check failed");

    require(value >= amount, "Insufficient value");
    B12.G1Point memory oldCommitment;

    {
      uint256 newy = uint256(keccak256(abi.encode(user, value - amount, z, x1, x2, y1, y2))) % BLS_MODULUS;
      uint256 delta = newy >= y ? newy - y : BLS_MODULUS - (y - newy);
      B12.G1Point memory lagrangeSetup = B12.G1Point(B12.Fp(x1, x2), B12.Fp(y1, y2));
      oldCommitment = commitment;
      commitment = B12_381Lib.g1Add(commitment, B12_381Lib.g1Mul(lagrangeSetup, delta));
    }

    emit UserBlobUpdated(oldCommitment, commitment, user, value, value - amount);
  }

  event AirdropUpdated(B12.G1Point oldCommitment, B12.G1Point newCommitment);

  function airdrop(B12.G1Point calldata airdropCommitment) external onlyOwner {
    B12.G1Point memory oldCommitment = commitment;
    commitment = B12_381Lib.g1Add(commitment, airdropCommitment);
    emit AirdropUpdated(oldCommitment, commitment);
  }
}
