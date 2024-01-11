// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Import OpenZeppelin ERC20, Ownable, ReentrancyGuard, ECDSA, and MessageHashUtils contracts
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

// ERC20 token contract with Ownable and ReentrancyGuard mixins
contract XRPSBridgeToken is ERC20, Ownable, ReentrancyGuard {
    // Use ECDSA for signature verification
    using ECDSA for bytes32;

    // Use MessageHashUtils for hashing
    using MessageHashUtils for bytes32;

    // Signer address variable 📝
    address private _signerAddress;

    // Mapping from address => nonce 🗂
    mapping(address => uint256) public nonces;

    // Constructor sets name, symbol, and signer address
    constructor(
        string memory name,
        string memory symbol,
        address signerAddress
    ) ERC20(name, symbol) Ownable(msg.sender) {
        // Require non-zero signer address 🙅
        require(
            signerAddress != address(0),
            "Signer address cannot be the zero address"
        );

        // Set signer address
        _signerAddress = signerAddress;
    }

    // Only owner can update signer address 🔐
    function updateSignerAddress(address newSignerAddress) public onlyOwner {
        // Require non-zero new signer address 🙅
        require(
            newSignerAddress != address(0),
            "New signer address cannot be the zero address"
        );

        // Update stored signer address
        _signerAddress = newSignerAddress;
    }

    // Mint tokens requiring valid signature 🔑
    function mint(
        uint256 amount,
        uint256 nonce,
        bytes memory signature
    ) public nonReentrant {
        // Check nonce matches 🕵️
        require(nonce == nonces[msg.sender], "Invalid nonce");

        // Verify signature is valid 🗳
        require(
            _verify(_hash(msg.sender, amount, nonce), signature),
            "Invalid signature"
        );

        // Increment nonce
        nonces[msg.sender] += 1;

        // Mint tokens 🪙
        _mint(msg.sender, amount);
    }

    // Hash message fields for signature 🖊
    function _hash(
        address account,
        uint256 amount,
        uint256 nonce
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(account, amount, nonce));
    }

    // Verify signature matches signer address 🖊⬅️🙋
    function _verify(
        bytes32 hash,
        bytes memory signature
    ) internal view returns (bool) {
        // Convert hash to Ethereum signed message hash
        bytes32 ethSignedHash = hash.toEthSignedMessageHash();

        // Recover address from signature
        address recovered = ethSignedHash.recover(signature);

        // Check recovered address matches signer
        return recovered == _signerAddress;
    }

    // Burn tokens 🔥
    function burn(uint256 amount) public virtual {
        _burn(_msgSender(), amount);
    }
}
