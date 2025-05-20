// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import { B12, B12_381Lib } from "../src/B12.sol";

uint256 constant BLS_MODULUS = 52435875175126190479447740508185965837690552500527637822603658699938581184513;

contract BaseTest is Test {
  function foo(uint256[2] memory arr) internal pure {
    arr[0] = 42;
  }

  function testFoo() public pure returns (uint256[2] memory) {
    uint256[2] memory x = [uint256(1), uint256(2)];
    foo(x);
    assertEq(x[0], 42);
    return x;
  }

  function testG2Mul() public view {
    B12.G2Point memory temp = B12_381Lib.Q1();
    B12_381Lib.g2Mul(temp, BLS_MODULUS - 1);
    assertEq(keccak256(abi.encode(B12_381Lib.negativeQ1())), keccak256(abi.encode(temp)));
  }

  function testG1Mul() public view {
    assertEq(
      keccak256(abi.encode(B12_381Lib.negativeP1())),
      keccak256(abi.encode(B12_381Lib.g1Mul(B12_381Lib.P1(), BLS_MODULUS - 1)))
    );
  }
}
